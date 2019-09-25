#!/usr/bin/env python3

import os
from subprocess import call
from sty import fg, bg, ef, rs
from lib import nmapParser
from utils import helper_lists
from utils import config_parser


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
        c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
        if not os.path.exists(c.getPath("report", "reportDir")):
            os.makedirs(c.getPath("report", "reportDir"))
        if not os.path.exists(c.getPath("report", "nmapDir")):
            os.makedirs(c.getPath("report", "nmapDir"))
        print(fg.cyan + "Running Nmap Top Open Ports" + fg.rs)
        hpl = helper_lists.topPortsToScan()
        topTCP = hpl.topTCP
        topTcpPortsString = ",".join(map(str, topTCP))
        nmap_command = c.getCmd("nmap", "nmapTopTcpPorts", topTcpPorts=topTcpPortsString)
        cmd_info = "[" + fg.li_green + "+" + fg.rs + "]"
        print(f"""{cmd_info} {fg.li_green}{nmap_command}{fg.rs}""")
        call(nmap_command, shell=True)

    def topUdpAllTcp(self):
        """topUdpAllTcp will run a full nmap tcp port scan, a top udp ports scan, and a nmap vulners script scan on found open
        ports from the initial nmap scan."""
        green = fg.li_green
        reset = fg.rs
        cmd_info = "[" + green + "+" + reset + "]"
        c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        tcpPorts = np.tcp_ports
        string_tcp_ports = ",".join(map(str, tcpPorts))
        hpl = helper_lists.topPortsToScan()
        topUDP = hpl.topUDP
        topUdpPortsString = ",".join(map(str, topUDP))
        commands = []
        commands.append(f"""echo {cmd_info}{green} '{c.getCmd("nmap", "nmapFullTcpScan")}' {reset}""")
        commands.append(c.getCmd("nmap", "nmapFullTcpScan"))
        commands.append(f"""echo {cmd_info}{green} '{c.getCmd("nmap", "nmapTopUdpScan", topUdpPorts=topUdpPortsString)}' {reset}""")
        commands.append(c.getCmd("nmap", "nmapTopUdpScan", topUdpPorts=topUdpPortsString))
        commands.append(f"""echo {cmd_info}{green} '{c.getCmd("nmap", "nmapVulners", openTcpPorts=string_tcp_ports)}' {reset}""")
        commands.append(c.getCmd("nmap", "nmapVulners", openTcpPorts=string_tcp_ports))
        self.processes = tuple(commands)
