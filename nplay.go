package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/hypebeast/go-osc/osc"
)

var fname = flag.String("r", "", "Filename to read from")
var oscIP = flag.String("osc-ip", "127.0.0.1", "OSC port")
var oscPort = flag.Int("osc-port", 3334, "OSC port")

const DIR_UNKNOWN = 0
const DIR_INCOMING = 1
const DIR_OUTGOING = 2

func makeMessage(data []byte, ci gopacket.CaptureInfo) (*osc.Message, error) {
	var (
		direction    int32
		transportStr string
		sport        int32
		dport        int32
	)
	length := ci.Length

	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	transport := packet.TransportLayer()
	transportType := transport.LayerType()
	switch {
	case transportType == layers.LayerTypeUDP:
		transportStr = "udp"
		sport = 12345
		//dport = int32(layers.UDPPort(transport.TransportFlow().Dst()))
		dport = 5432
		log.Printf("dport: %d\n", dport)
	case transportType == layers.LayerTypeTCP:
		transportStr = "tcp"
	default:
		transportStr = "unknown"
	}

	for _, layer := range packet.Layers() {
		fmt.Println("PACKET LAYER:", layer.LayerType())
	}

	message := osc.NewMessage("/gotpacket")
	message.Append(int32(direction)) // Direction
	message.Append(int32(length))    // packet length
	message.Append(sport)            // sport
	message.Append(dport)            // dport
	message.Append("http")           // highest layer
	message.Append(transportStr)     // transport layer
	message.Append(int32(98282))     // ip_dst
	message.Append(int32(23))        // ip_src
	message.Append("example.com")    // host
	return message, nil
}

var lastTS time.Time
var lastSend time.Time

func sendPacket(client *osc.Client, data []byte, ci gopacket.CaptureInfo) error {
	intervalInCapture := ci.Timestamp.Sub(lastTS)
	elapsedTime := time.Since(lastSend)
	if (intervalInCapture > elapsedTime) && !lastSend.IsZero() {
		time.Sleep(intervalInCapture - elapsedTime)
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
