import sys
import time
import argparse
import ipaddress

import pyshark
from OSC import OSCClient, OSCMessage, OSCBundle

class OSCClientWriter(object):
    def __init__(self, host, port, time_warp=1.0):
        self.client = OSCClient()
        self.client.connect((host, port))
        self.start_time = time.time()
        self.first_timestamp = None
        self.time_warp = time_warp
        self.my_ip = '10.0.11.237'

    def got_packet(self, packet):
        try:
            timestamp = float(packet.sniff_timestamp)
            if self.first_timestamp is None:
                self.first_timestamp = timestamp
            offset = (timestamp - self.first_timestamp)*self.time_warp
            print("Offsetting by %s" % offset)

            direction = 2 # 2: nor incoming, nor outgoing
                          # 1: is incoming
                          # 0: is outgoing
            is_incoming = False
            if packet.ip.dst == self.my_ip:
                is_incoming = True
                direction = 1
            elif packet.ip.src == self.my_ip:
                direction = 0

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
        sport = 0
        dport = 0
        try:
            sport = packet.udp.srcport
            dport = packet.udp.dstport
        except AttributeError:
            pass
        try:
            sport = packet.tcp.srcport
            dport = packet.tcp.dstport
        except AttributeError:
            pass

        pkt_msg= OSCMessage('/gotpacket')
        pkt_msg.append(direction, 'i')
        pkt_msg.append(packet.length, 'i')
        pkt_msg.append(sport, 'i')
        pkt_msg.append(dport, 'i')

        pkt_msg.append(packet.highest_layer, 's')
        pkt_msg.append(packet.transport_layer, 's')
        pkt_msg.append(packet.ip.src, 's')
        pkt_msg.append(packet.ip.dst, 's')
        pkt_msg.append(packet.ip.host, 's')
        pkt_bundle = OSCBundle('/gotpacket',
                               time=self.start_time + offset)
        pkt_bundle.append(pkt_msg)
        self.client.send(pkt_bundle)

def start_capture(interface, osc_client):
    capture = pyshark.LiveRingCapture(interface=interface,
                                      ring_file_size=2**14) # 16MB
    for packet in capture.sniff_continuously():
        osc_client.got_packet(packet)

def read_pcap(pcap_file, osc_client):
    capture = pyshark.FileCapture(pcap_file)
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
    parser.add_argument('--time-warp', default='1.0',
            help='Factor by which to warp time (ex. 2.0 means 2 times slower)',
            type=float)

    args = parser.parse_args()
    try:
        osc_server_host, osc_server_port = args.osc_server.split(':')
        osc_server_port = int(osc_server_port)
    except Exception:
        print("Error in reading osc-server")
        parser.help()
        sys.exit(1)

    osc_client = OSCClientWriter(osc_server_host, osc_server_port,
                                 time_warp=args.time_warp)

    if args.pcap:
        print("Reading from PCAP file: %s" % args.pcap)
        read_pcap(args.pcap, osc_client)
    else:
        print("Sniffing on interface: %s" % args.interface)
        start_capture(args.interface, osc_client)

if __name__ == "__main__":
    main()
