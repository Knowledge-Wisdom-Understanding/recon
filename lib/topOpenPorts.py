#!/usr/bin/env python3

import os
from subprocess import call
from sty import fg, bg, ef, rs, RgbFg

# import sys


class TopOpenPorts:
    def __init__(self, target):
        self.target = target

    def Scan(self):
        if not os.path.exists(f"{self.target}-Report".):
            os.makedirs(f"{self.target}-Report")
        if not os.path.exists(f"{self.target}-Report/nmap"):
            os.makedirs(f"{self.target}-Report/nmap")
        c = fg.cyan + "Running Nmap Top Open Ports" + fg.rs
        print(c)
        nmap_command = f"nmap -vv -Pn -sV -T3 --max-retries 1 --max-scan-delay 20 --top-ports 10000 -oA {self.target}-Report/nmap/top-ports-{self.target} {self.target}"
        cmd_info = "[" + fg.li_green + "+" + fg.rs + "]"
        print(cmd_info, nmap_command)
        call(nmap_command, shell=True)

    def fullScan(self):
        c = fg.cyan + "Running Full Tcp Nmap Port Scan" + fg.rs
        print(c)
        nmap_command = f"nmap -vv -Pn -A -p- -T4 --script-timeout 2m -oA {self.target}-Report/nmap/full-tcp-scan-{self.target} {self.target}"
        cmd_info = "[" + fg.li_green + "+" + fg.rs + "]"
        print(cmd_info, nmap_command)
        call(nmap_command, shell=True)

