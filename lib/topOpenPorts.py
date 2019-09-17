#!/usr/bin/env python3

import os
from subprocess import call
from sty import fg, bg, ef, rs
from lib import nmapParser
from utils import helper_lists

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
        hpl = helper_lists.topPortsToScan()
        topTCP = hpl.topTCP
        stringerT = ",".join(map(str, topTCP))
        nmap_command = f"nmap -vv -Pn -sV -sC -p {stringerT} --script-timeout 2m -oA {self.target}-Report/nmap/top-ports-{self.target} {self.target}"
        cmd_info = "[" + fg.li_green + "+" + fg.rs + "]"
        print(cmd_info, nmap_command)
        call(nmap_command, shell=True)

    def topUdpAllTcp(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        tcpPorts = np.tcp_ports
        string_tcp_ports = ",".join(map(str, tcpPorts))
        hpl = helper_lists.topPortsToScan()
        topUDP = hpl.topUDP
        stringerU = ",".join(map(str, topUDP))
        commands = (
            f"nmap -vv -Pn -sC -sV -O -p- -T4 --script-timeout 2m -oA {self.target}-Report/nmap/full-tcp-scan-{self.target} {self.target}",
            f"nmap -sUV -vv --reason -T4 --max-retries 3 --max-rtt-timeout 150ms -pU:{stringerU} -oA {self.target}-Report/nmap/top-udp-ports {self.target}",
            f"nmap -vv -sV -Pn --script nmap-vulners -p {string_tcp_ports} -oA {self.target}-Report/nmap/vulnscan-{self.target} {self.target}",
        )
        self.processes = commands

