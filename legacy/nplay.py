import sys
import time
import argparse
import ipaddress

import pyshark

from pythonosc import osc_message_builder, osc_bundle_builder
from pythonosc import udp_client

# 2: nor incoming, nor outgoing
# 1: is incoming
# 0: is outgoing
DIR_INCOMING = 1
DIR_OUTGOING = 0
DIR_NONE = 2

def compute_direction(src, dst, my_ip):
    if my_ip is not None:
        if dst == my_ip:
            return DIR_INCOMING
        elif src == my_ip:
            return DIR_OUTGOING
    else:
        if src.is_private:
            return DIR_OUTGOING
        elif dst.is_private:
            return DIR_INCOMING
    return DIR_NONE

class OSCClientWriter(object):
    def __init__(self, host, port, my_ip, time_warp=1.0):
        self.client = udp_client.SimpleUDPClient(host, port)

        self.start_time = time.time()
        self.first_timestamp = None

        self.time_warp = time_warp
        self.my_ip = my_ip
        self.idx = 0

    def got_packet(self, packet):
        if not hasattr(packet, 'ip'):
            print("Skipping non-ip packet")
            return

        self.idx += 1
        try:
            ip_src = ipaddress.ip_address(packet.ip.src)
            ip_dst = ipaddress.ip_address(packet.ip.dst)

            timestamp = float(packet.sniff_timestamp)
            if self.first_timestamp is None:
                self.first_timestamp = float(timestamp)
            offset = (float(timestamp) - self.first_timestamp)*float(self.time_warp)
            print("Offsetting by %s" % offset)

            direction = compute_direction(ip_src, ip_dst, self.my_ip)

            relevant_data = (
                    'in' if direction == DIR_INCOMING else 'out',
                    packet.length,
                    packet.transport_layer,
                    packet.ip.src,
                    packet.ip.dst,
                    packet.ip.host,
                    packet.highest_layer,
                    packet.sniff_timestamp)
            pkt_string = ",".join(relevant_data)
        except Exception as exc:
            print("FAILED")
            print(exc)
            print("\n\n")
            return
        print(pkt_string)

        sport = 0
        dport = 0
        try:
            sport = int(packet.udp.srcport)
            dport = int(packet.udp.dstport)
        except AttributeError:
            pass
        try:
            sport = int(packet.tcp.srcport)
            dport = int(packet.tcp.dstport)
        except AttributeError:
            pass

        msg = osc_message_builder.OscMessageBuilder(address='/gotpacket')
        msg.add_arg(direction, 'i')
        msg.add_arg(int(packet.length), 'i')
        msg.add_arg(sport, 'i')
        msg.add_arg(dport, 'i')

        msg.add_arg(packet.highest_layer, 's')
        msg.add_arg(packet.transport_layer, 's')

        msg.add_arg(int(ip_dst) >> 24, 'i')
        msg.add_arg(int(ip_src) >> 24, 'i')
        #pkt_msg.append(packet.ip.src, 's')
        #pkt_msg.append(packet.ip.dst, 's')
        msg.add_arg(packet.ip.host, 's')
        timestamp = self.start_time + offset + self.idx * 20
        print("ts: %f" % timestamp)
        bundle = osc_bundle_builder.OscBundleBuilder(timestamp)
        bundle.add_content(msg.build())
        built_bundle = bundle.build()
        print("bundle: %s" % built_bundle.dgram)
        self.client.send(built_bundle)

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
    parser.add_argument('--interface', default='en0',
            help='The interface to listen on for incoming messages')
    parser.add_argument('--pcap',
            help='The pcap file to read packets from')
    parser.add_argument('--my-ip',
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

    my_ip = None
    if args.my_ip:
        my_ip = ipaddress.ip_address(args.my_ip)

    osc_client = OSCClientWriter(osc_server_host,
                                 osc_server_port,
                                 my_ip=my_ip,
                                 time_warp=args.time_warp)

    if args.pcap:
        print("> Reading from PCAP file: %s" % args.pcap)
        read_pcap(args.pcap, osc_client)
    else:
        print("> Sniffing on interface: %s" % args.interface)
        start_capture(args.interface, osc_client)

if __name__ == "__main__":
    main()
