#!/usr/bin/env python3

import os
from subprocess import call
from sty import fg, bg, ef, rs
from lib import nmapParser
from utils import helper_lists
from utils import config_paths


class TopOpenPorts:
    def __init__(self, target):
        self.target = target
        self.processes = ""

    def Scan(self):
        c = config_paths.Configurator(self.target)
        c.createConfig()
        if not os.path.exists(f"""{c.getPath("reportDir")}"""):
            os.makedirs(f"""{c.getPath("reportDir")}""")
        if not os.path.exists(f"""{c.getPath("nmapDir")}"""):
            os.makedirs(f"""{c.getPath("nmapDir")}""")
        print(fg.cyan + "Running Nmap Top Open Ports" + fg.rs)
        hpl = helper_lists.topPortsToScan()
        topTCP = hpl.topTCP
        stringerT = ",".join(map(str, topTCP))
        nmap_command = f"""nmap -vv -Pn -sV -sC -p {stringerT} --script-timeout 2m -oA {c.getPath("top_ports")} {self.target}"""
        cmd_info = "[" + fg.li_green + "+" + fg.rs + "]"
        print(f"""{cmd_info} {fg.li_green}{nmap_command}{fg.rs}""")
        call(nmap_command, shell=True)

    def topUdpAllTcp(self):
        green = fg.li_green
        reset = fg.rs
        cmd_info = "[" + green + "+" + reset + "]"
        c = config_paths.Configurator(self.target)
        c.createConfig()
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        tcpPorts = np.tcp_ports
        string_tcp_ports = ",".join(map(str, tcpPorts))
        hpl = helper_lists.topPortsToScan()
        topUDP = hpl.topUDP
        stringerU = ",".join(map(str, topUDP))
        commands = (
            f"""echo {cmd_info} {green} 'nmap -vv -Pn -sC -sV -O -p- -T4 --script-timeout 2m -oA {c.getPath("full_tcp")} {self.target}' {reset}""",
            f"""nmap -vv -Pn -sC -sV -O -p- -T4 --script-timeout 2m -oA {c.getPath("full_tcp")} {self.target}""",
            f"""echo {cmd_info} {green} 'nmap -sUV -vv --reason -T4 --max-retries 3 --max-rtt-timeout 150ms -pU:{stringerU} -oA {c.getPath("top_udp_ports")} {self.target}' {reset}""",
            f"""nmap -sUV -vv --reason -T4 --max-retries 3 --max-rtt-timeout 150ms -pU:{stringerU} -oA {c.getPath("top_udp_ports")} {self.target}""",
            f"""echo {cmd_info} {green} 'nmap -vv -sV -Pn --script nmap-vulners -p {string_tcp_ports} -oA {c.getPath("vulners")} {self.target}' {reset}""",
            f"""nmap -vv -sV -Pn --script nmap-vulners -p {string_tcp_ports} -oA {c.getPath("vulners")} {self.target}""",
        )
        self.processes = commands

