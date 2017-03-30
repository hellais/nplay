import sys
import argparse
import ipaddress

import pyshark
from pythonosc import osc_message_builder
from pythonosc import udp_client

class OSCClientWriter(object):
    def __init__(self, host, port):
        self.client = udp_client.SimpleUDPClient(host, port)

    def got_packet(self, packet):
        #my_ip = '192.168.1.3'
        my_ip = '10.0.11.237'
        try:
            is_incoming = False
            if packet.ip.dst == my_ip:
                is_incoming = True
            relevant_data = (
                    'in' if is_incoming else 'out',
                    packet.length,
                    packet.transport_layer,
                    packet.ip.src,
                    packet.ip.dst,
                    packet.ip.host,
                    packet.highest_layer,
                    packet.sniff_timestamp)
            pkt_string = ",".join(relevant_data)
        except Exception:
            print("FAILED")
            print(packet)
            print("\n\n")
            return
        print(pkt_string)
        self.client.send_message(
                '/transport/{}'.format(packet.transport_layer),
                packet.highest_layer
        )

        if is_incoming:
            first_octet = ipaddress.IPv4Address(packet.ip.src).packed[0]
            dst = 'in'
        else:
            first_octet = ipaddress.IPv4Address(packet.ip.dst).packed[0]
            dst = 'out'
        self.client.send_message(
                '/dst/{}'.format(dst),
                first_octet
        )
        self.client.send_message(
                '/gotpacket',
                list(relevant_data)
        )



def start_capture(interface, osc_client):
    capture = pyshark.LiveCapture(interface=interface)
    for packet in capture.sniff_continuously():
        osc_client.got_packet(packet)

def read_pcap(pcap_file, osc_client):
    capture = pyshark.FileCapture(pcap_file)
    # XXX we probably want to delay packets here and possibly reorder them
    for packet in capture:
        osc_client.got_packet(packet)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--osc-server', default='127.0.0.1:3334',
            help='The address of the open sound control server to send '
            'messages to')
    parser.add_argument('--interface', default='en1',
            help='The interface to listen on for incoming messages')
    parser.add_argument('--pcap',
            help='The pcap file to read packets from')
    args = parser.parse_args()
    try:
        osc_server_host, osc_server_port = args.osc_server.split(':')
        osc_server_port = int(osc_server_port)
    except Exception:
        print("Error in reading osc-server")
        parser.help()
        sys.exit(1)

    osc_client = OSCClientWriter(osc_server_host, osc_server_port)

    if args.pcap:
        print("Reading from PCAP file: %s" % args.pcap)
        read_pcap(args.pcap, osc_client)
    else:
        print("Sniffing on interface: %s" % args.interface)
        start_capture(args.interface, osc_client)

if __name__ == "__main__":
    main()
