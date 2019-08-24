#!/usr/bin/env python3

import os
import subprocess as s
from sty import fg, bg, ef, rs, RgbFg
from lib import nmapParser

# import sys


class NmapOpenPorts:
    def __init__(self, target):
        self.target = target

    def Scan(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        tcpPorts = np.tcp_ports
        if len(tcpPorts) == 0:
            pass
        else:
            tcp_string_ports = ",".join(map(str, tcpPorts))
            # print(http_string_ports)
            nmap_command = "nmap -vv -Pn -sC -sV -p {} --script-timeout 2m -oA {}-Report/nmap/tcp-scripts-{} {}".format(
                tcp_string_ports, self.target, self.target, self.target
            )
            green_plus = fg.li_green + "+" + fg.rs
            cmd_info = "[" + green_plus + "]"
            print(cmd_info, nmap_command)
            s.call(nmap_command, shell=True)
