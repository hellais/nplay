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

const DIR_UNKNOWN = 0
const DIR_INCOMING = 1
const DIR_OUTGOING = 2

func computeDirection(srcIP net.IP, dstIP net.IP) int32 {
	ip := srcIP
	_, private24BitBlock, _ := net.ParseCIDR("10.0.0.0/8")
	_, private20BitBlock, _ := net.ParseCIDR("172.16.0.0/12")
	_, private16BitBlock, _ := net.ParseCIDR("192.168.0.0/16")
	isPrivate := private24BitBlock.Contains(ip) || private20BitBlock.Contains(ip) || private16BitBlock.Contains(ip)
	if isPrivate {
		return DIR_OUTGOING
	}
	return DIR_INCOMING
}

func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

func makeMessage(data []byte, ci gopacket.CaptureInfo) (*osc.Message, error) {
	var (
		direction    int32
		transportStr string
		appLayerStr  string
		sport        int32
		dport        int32
		srcIP        net.IP
		dstIP        net.IP
		srcIPNum     int32
		dstIPNum     int32
	)
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
		return nil, fmt.Errorf("no network type")
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
		return nil, fmt.Errorf("unsupported network type")
	}

	// Transport layer features
	transport := packet.TransportLayer()
	var transportType gopacket.LayerType
	if transport != nil {
		transportType = transport.LayerType()
	}
	switch {
	case transportType == layers.LayerTypeUDP:
		transportStr = "udp"
		udp := transport.(*layers.UDP)
		sport = int32(udp.SrcPort)
		dport = int32(udp.DstPort)
	case transportType == layers.LayerTypeTCP:
		transportStr = "tcp"
		tcp := transport.(*layers.TCP)
		sport = int32(tcp.SrcPort)
		dport = int32(tcp.DstPort)
	default:
		transportStr = "unknown"
	}
	direction = computeDirection(srcIP, dstIP)
	srcIPNum = int32(ip2int(srcIP) << 24)
	dstIPNum = int32(ip2int(dstIP) << 24)

	// Application layer features
	application := packet.ApplicationLayer()
	if application != nil {
		appLayerStr = fmt.Sprintf("%s", application.LayerType())
	}

	message := osc.NewMessage("/gotpacket")
	message.Append(direction)     // Direction
	message.Append(int32(length)) // packet length
	message.Append(sport)         // sport
	message.Append(dport)         // dport
	message.Append(appLayerStr)   // highest layer
	message.Append(transportStr)  // transport layer
	message.Append(srcIPNum)      // ip_dst
	message.Append(dstIPNum)      // ip_src
	return message, nil
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

	message, err := makeMessage(data, ci)
	if err != nil {
		log.Printf("Failed to makeMessage: %s\n", err)
	} else {
		client.Send(message)
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
