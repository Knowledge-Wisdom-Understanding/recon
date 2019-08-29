#!/usr/bin/env python3

import os
from subprocess import call
from sty import fg, bg, ef, rs, RgbFg
from lib import nmapParser

# import sys


class SnmpEnum:
    def __init__(self, target):
        self.target = target
        self.processes = ""

    def Scan(self):
        if not os.path.exists(f"{self.target}-Report"):
            os.makedirs(f"{self.target}-Report")
        if not os.path.exists(f"{self.target}-Report/snmp"):
            os.makedirs(f"{self.target}-Report/snmp")
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        tcpPorts = np.tcp_ports
        commands = (
            f"onesixtyone -c /usr/share/doc/onesixtyone/dict.txt $rhost | tee -a snmpenum-$rhost.log",
            f"snmp-check -c public -v 1 -d $rhost | tee -a {self.target}-Report/snmpenum.log",
            f"nmap -v -sV -Pn --script nmap-vulners -p {tcpPorts} -oA {self.target}-Report/nmap/vulnscan-{self.target} {self.target}",
        )
        self.processes = commands
