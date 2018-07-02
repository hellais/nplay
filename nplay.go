package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/hypebeast/go-osc/osc"
)

var fname = flag.String("r", "", "Filename to read from")
var timeWarp = flag.Float64("w", 1.0, "Factor to warp time by")
var oscIP = flag.String("osc-ip", "127.0.0.1", "OSC port")
var oscPort = flag.Int("osc-port", 3334, "OSC port")

type TriggerType int64

const (
	TRIG_UNKNOWN  TriggerType = 1
	TRIG_INCOMING TriggerType = 10
	TRIG_OUTGOING TriggerType = 11
	TRIG_UDP      TriggerType = 20
	TRIG_TCP_NSA  TriggerType = 30 // Not SYN or ACK
	TRIG_TCP_SYN  TriggerType = 31
	TRIG_TCP_ACK  TriggerType = 32
	TRIG_TCP_FIN  TriggerType = 33
	TRIG_TCP_RST  TriggerType = 34
	TRIG_ICMP     TriggerType = 40
)

func getTriggerName(trig TriggerType) string {
	switch trig {
	case TRIG_UNKNOWN:
		return "/type/unknown"
	case TRIG_INCOMING:
		return "/type/incoming"
	case TRIG_OUTGOING:
		return "/type/outgoing"
	case TRIG_UDP:
		return "/type/udp"
	case TRIG_TCP_NSA:
		return "/type/tcp_nsa"
	case TRIG_TCP_SYN:
		return "/type/tcp_syn"
	case TRIG_TCP_ACK:
		return "/type/tcp_ack"
	case TRIG_TCP_FIN:
		return "/type/tcp_fin"
	case TRIG_TCP_RST:
		return "/type/tcp_rst"
	case TRIG_ICMP:
		return "/type/icmp"
	default:
		return "/type/unknown"
	}
}

func computeDirection(srcIP net.IP, dstIP net.IP) TriggerType {
	ip := srcIP
	_, private24BitBlock, _ := net.ParseCIDR("10.0.0.0/8")
	_, private20BitBlock, _ := net.ParseCIDR("172.16.0.0/12")
	_, private16BitBlock, _ := net.ParseCIDR("192.168.0.0/16")
	isPrivate := private24BitBlock.Contains(ip) || private20BitBlock.Contains(ip) || private16BitBlock.Contains(ip)
	if isPrivate {
		return TRIG_OUTGOING
	}
	return TRIG_INCOMING
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func makeMessage(data []byte, ci gopacket.CaptureInfo) ([]*osc.Message, error) {
	var (
		direction    TriggerType
		transportStr string
		appLayerStr  string
		sport        int32
		dport        int32
		srcIP        net.IP
		dstIP        net.IP
		srcIPNum     int32
		dstIPNum     int32
		triggers     []TriggerType
		messages     []*osc.Message
	)
	// The trigger signals that we send are the following:
	// * INCOMING
	// * OUTGOING
	// * UDP
	// * TCP (!SYNC & !ACK)
	// * TCP (SYN)
	// * TCP (ACK)
	// * TCP (FIN)
	// * TCP (RST) (rare)
	// * ICMP
	// triggers = append(triggers, TRIG_UDP)

	length := ci.Length

	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

	// XXX debug
	/*
		for _, layer := range packet.Layers() {
			fmt.Println("PACKET LAYER:", layer.LayerType())
		}
	*/

	// Network layer features
	network := packet.NetworkLayer()
	if network == nil {
		return messages, fmt.Errorf("no network type")
	}
	networkType := network.LayerType()
	if networkType == layers.LayerTypeIPv4 {
		ipv4 := network.(*layers.IPv4)
		srcIP = ipv4.SrcIP
		dstIP = ipv4.DstIP
	} else if networkType == layers.LayerTypeIPv6 {
		ipv6 := network.(*layers.IPv6)
		srcIP = ipv6.SrcIP
		dstIP = ipv6.DstIP
	} else {
		return messages, fmt.Errorf("unsupported network type")
	}

	// Transport layer features
	transport := packet.TransportLayer()
	var transportType gopacket.LayerType
	if transport != nil {
		transportType = transport.LayerType()
	}
	switch {
	case transportType == layers.LayerTypeICMPv4:
		transportStr = "icmp4"
		triggers = append(triggers, TRIG_ICMP)
	case transportType == layers.LayerTypeICMPv6:
		transportStr = "icmp6"
		triggers = append(triggers, TRIG_ICMP)
	case transportType == layers.LayerTypeUDP:
		transportStr = "udp"
		udp := transport.(*layers.UDP)
		sport = int32(udp.SrcPort)
		dport = int32(udp.DstPort)
		triggers = append(triggers, TRIG_UDP)
	case transportType == layers.LayerTypeTCP:
		transportStr = "tcp"
		tcp := transport.(*layers.TCP)
		sport = int32(tcp.SrcPort)
		dport = int32(tcp.DstPort)

		if tcp.FIN == true {
			triggers = append(triggers, TRIG_TCP_FIN)
		}
		if tcp.RST == true {
			triggers = append(triggers, TRIG_TCP_RST)
		}
		if tcp.ACK == true {
			triggers = append(triggers, TRIG_TCP_ACK)
		}
		if tcp.SYN == true {
			triggers = append(triggers, TRIG_TCP_SYN)
		}
		if !tcp.SYN && !tcp.ACK && !tcp.RST && !tcp.FIN {
			triggers = append(triggers, TRIG_TCP_NSA)
		}
	default:
		transportStr = "unknown"
	}
	// XXX remove me
	//if transportStr != "tcp" {
	//	return nil, fmt.Errorf("no network type")
	//}
	direction = computeDirection(srcIP, dstIP)
	triggers = append(triggers, direction)

	//log.Printf("%s - %s\n", srcIP.String(), dstIP.String())
	//log.Printf("%d - %d\n", ip2int(srcIP), ip2int(dstIP))
	srcIPNum = int32(ip2int(srcIP) >> 24)
	dstIPNum = int32(ip2int(dstIP) >> 24)

	// Application layer features
	application := packet.ApplicationLayer()
	if application != nil {
		appLayerStr = fmt.Sprintf("%s", application.LayerType())
	}

	for _, trig := range triggers {
		message := osc.NewMessage(getTriggerName(trig))
		message.Append(int32(direction)) // Direction
		message.Append(int32(length))    // packet length
		message.Append(sport)            // sport
		message.Append(dport)            // dport
		message.Append(appLayerStr)      // highest layer
		message.Append(transportStr)     // transport layer
		message.Append(srcIPNum)         // ip_dst
		message.Append(dstIPNum)         // ip_src
		messages = append(messages, message)
	}
	return messages, nil
}

var lastTS time.Time
var lastSend time.Time

func sendPacket(client *osc.Client, data []byte, ci gopacket.CaptureInfo) error {
	intervalInCapture := ci.Timestamp.Sub(lastTS) * time.Duration(*timeWarp)
	elapsedTime := time.Since(lastSend)
	if (intervalInCapture > elapsedTime) && !lastSend.IsZero() {
		time.Sleep((intervalInCapture - elapsedTime))
	}
	lastSend = time.Now()

	messages, err := makeMessage(data, ci)
	if err != nil {
		log.Printf("Failed to makeMessage: %s\n", err)
	} else {
		for _, msg := range messages {
			log.Println("Sending packet")
			client.Send(msg)
		}
	}

	lastTS = ci.Timestamp
	return nil
}

func main() {
	flag.Parse()

	if *fname == "" {
		log.Printf("fname: %s\n", *fname)
		log.Fatal("Need a input file")
	}

	log.Printf("Warping time by: %f\n", *timeWarp)

	handleRead, err := pcap.OpenOffline(*fname)
	if err != nil {
		log.Fatal("PCAP OpenOffline error (handle to read packet):", err)
	}
	defer handleRead.Close()

	start := time.Now()
	client := osc.NewClient(*oscIP, *oscPort)

	for {
		data, ci, err := handleRead.ReadPacketData()
		switch {
		case err == io.EOF:
			fmt.Printf("\nFinished in %s", time.Since(start))
			return
		case err != nil:
			log.Printf("Failed to read packet: %s\n", err)
		default:
			if err = sendPacket(client, data, ci); err != nil {
				log.Printf("Failed to send packet: %s\n", err)
			}
		}
	}

}
