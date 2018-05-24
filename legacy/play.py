#!/usr/bin/env python
import sys
from subprocess import Popen, PIPE

class Packet(object):
    def __init__(self, line):
        self.line = line
        (self.src_address, self.dst_address,
         self.tcp_sport, self.tcp_dport,
         self.udp_sport, self.udp_dport,
         self.protocol, self.dns_query) = line.split(",")

class TsharkHandler(object):
    _tshark_bin = "tshark"
    include_fields = [
        "ip.addr",
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport",
        "_ws.col.Protocol",
        "dns.qry.name"
    ]
    _stderr = None
    _stdout = None

    def __init__(self, iface="en1"):
        self.iface = iface

    def _compose_command(self):
        command = [self._tshark_bin]
        command.append("-i")
        command.append(self.iface)

        command.append("-E")
        command.append("separator=,")

        command.append("-T")
        command.append("fields")

        for field in self.include_fields:
            command.append("-e")
            command.append(field)
        return command

    def got_packet(self, packet):
        sys.stdout.write(packet.line)

    def start(self):
        command = self._compose_command()
        self._popen = Popen(command, stdout=PIPE)
        print ' '.join(command)
        print "ABOUT TO"
        for line in iter(self._popen.stdout.readline, ''):
            sys.stdout.write(line)
            sys.stdout.write("\n")
            print("HELLO")
            self.got_packet(Packet(line))

def main():
    tshark_handler = TsharkHandler()
    tshark_handler.start()

if __name__ == "__main__":
    main()
