#!/usr/bin/env python3

import os
from subprocess import call
from sty import fg, bg, ef, rs, RgbFg
from lib import nmapParser

# import sys


class TopOpenPorts:
    def __init__(self, target):
        self.target = target
        self.processes = ""

    def Scan(self):
        if not os.path.exists(f"{self.target}-Report"):
            os.makedirs(f"{self.target}-Report")
        if not os.path.exists(f"{self.target}-Report/nmap"):
            os.makedirs(f"{self.target}-Report/nmap")
        c = fg.cyan + "Running Nmap Top Open Ports" + fg.rs
        print(c)
        nmap_command = f"nmap -vv -Pn -sV -sC -T4 --max-scan-delay 20 --top-ports 10000 --script-timeout 2m -oA {self.target}-Report/nmap/top-ports-{self.target} {self.target}"
        cmd_info = "[" + fg.li_green + "+" + fg.rs + "]"
        print(cmd_info, nmap_command)
        call(nmap_command, shell=True)

    def topUdpAllTcp(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        tcpPorts = np.tcp_ports
        string_tcp_ports = ",".join(map(str, tcpPorts))
        commands = (
            f"nmap -vv -Pn -sC -sV -O -p- -T4 --script-timeout 2m -oA {self.target}-Report/nmap/full-tcp-scan-{self.target} {self.target}",
            f"nmap -sUV -v --reason -T4 --max-retries 3 --max-rtt-timeout 150ms -pU:53,67-69,111,123,135,137-139,161-162,445,500,514,520,631,998,1434,1701,1900,4500,5353,49152,49154 -oA {self.target}-Report/nmap/top-udp-ports {self.target}",
            f"nmap -v -sV -Pn --script nmap-vulners -p {string_tcp_ports} -oA {self.target}-Report/nmap/vulnscan-{self.target} {self.target}",
        )
        self.processes = commands

