#!/usr/bin/env python3

import os
from subprocess import call
from sty import fg, bg, ef, rs, RgbFg

# import sys


class TopOpenPorts:
    def __init__(self, target):
        self.target = target

    def Scan(self):
        #
        if not os.path.exists("{}-Report".format(self.target)):
            os.makedirs("{}-Report".format(self.target))
        if not os.path.exists("{}-Report/nmap".format(self.target)):
            os.makedirs("{}-Report/nmap".format(self.target))
        c = fg.cyan + "Running Nmap Top Open Ports" + fg.rs
        print(c)
        nmap_command = "nmap -vv -Pn -sV -T3 --max-retries 1 --max-scan-delay 20 --top-ports 10000 -oA {}-Report/nmap/top-ports-{} {}".format(
            self.target, self.target, self.target
        )
        # nmapDebugging = "nmap -vv -Pn -sV -p 80 -oA nmap/top-ports-{} {}".format(
        #     self.target, self.target)
        green_plus = fg.li_green + "+" + fg.rs
        cmd_info = "[" + green_plus + "]"
        print(cmd_info, nmap_command)
        call(nmap_command, shell=True)
        # print(cmd_info, nmapDebugging)
        # s.call(nmapDebugging, shell=True)

    def fullScan(self):
        c = fg.cyan + "Running Full Tcp Nmap Port Scan" + fg.rs
        print(c)
        nmap_command = "nmap -vv -Pn -A -p- -T4 --script-timeout 2m -oA {}-Report/nmap/full-tcp-scan-{} {}".format(
            self.target, self.target, self.target
        )
        # nmapDebugging = "nmap -vv -Pn -sV -p 22,80 -oA nmap/top-ports-{} {}".format(
        #     self.target, self.target)
        green_plus = fg.li_green + "+" + fg.rs
        cmd_info = "[" + green_plus + "]"
        print(cmd_info, nmap_command)
        call(nmap_command, shell=True)

        # def OpenServices(self):
        #     print("todo")

        # def Results(self):
        #     print("todo")
