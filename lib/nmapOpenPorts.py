#!/usr/bin/env python3

import os
from subprocess import call
from sty import fg, bg, ef, rs, RgbFg
from lib import nmapParser

# import sys


class NmapOpenPorts:
    def __init__(self, target):
        self.target = target

    def Scan(self):
        cwd = os.getcwd()
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        tcpPorts = np.tcp_ports
        if len(tcpPorts) == 0:
            pass
        else:
            tcp_string_ports = ",".join(map(str, tcpPorts))
            # print(http_string_ports)
            nmap_command = f"nmap -vv -Pn -sC -sV -p {tcp_string_ports} --script-timeout 2m -oA {self.target}-Report/nmap/tcp-scripts-{self.target} {self.target}"
            cmd_info = "[" + fg.li_green + "+" + fg.rs + "]"
            print(cmd_info, nmap_command)
            call(nmap_command, shell=True)
            # vulnscan_cmd = f"cd /opt/ReconScan && python3 vulnscan.py {cwd}/{self.target}-Report/nmap/tcp-scripts-{self.target}.xml && cd - &>/dev/null"
            # print(cmd_info, vulnscan_cmd)
            # call(vulnscan_cmd, shell=True)
