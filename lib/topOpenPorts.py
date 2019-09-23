#!/usr/bin/env python3

import os
from subprocess import call
from sty import fg, bg, ef, rs
from lib import nmapParser
from utils import helper_lists
from utils import config_paths


class TopOpenPorts:
    """The TopOpenPorts Class holds functions that will run nmap scan top 363 custom common ports
    scan, top UDP ports, Nmap vulners scripts, along with a Full TCP Scan to be thorough."""

    def __init__(self, target):
        self.target = target
        self.processes = ""

    def Scan(self):
        """The Scan() function will run the initial nmap Top Tcp ports scan with enumerate
        versions and nmap's default safe scripts via the -sC and -sV flags. -Pn will ignore ping scan
        and the script-timeout is set to 5 minutes as sometimes https scripts can get stuck and
        output 100's of lines of unnecessary output which will slow the scan time down. 5 minutes is a good timeout
        setting."""
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
        nmap_command = f"""nmap -vv -Pn -sV -sC -p {stringerT} --script-timeout 5m -oA {c.getPath("top_ports")} {self.target}"""
        cmd_info = "[" + fg.li_green + "+" + fg.rs + "]"
        print(f"""{cmd_info} {fg.li_green}{nmap_command}{fg.rs}""")
        call(nmap_command, shell=True)

    def topUdpAllTcp(self):
        """topUdpAllTcp will run a full nmap tcp port scan, a top udp ports scan, and a nmap vulners script scan on found open
        ports from the initial nmap scan."""
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

