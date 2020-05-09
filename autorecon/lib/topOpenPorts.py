#!/usr/bin/env python3

import os
from subprocess import call
from sty import fg
from autorecon.lib import nmapParser
from autorecon.utils import helper_lists
from autorecon.utils import config_parser
from autorecon.utils import run_commands


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
        rc = run_commands.RunCommands(self.target)
        c = config_parser.CommandParser(f"{os.path.expanduser('~')}/.config/autorecon/config.yaml", self.target)
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
        rc.loginator(nmap_command)
        call(nmap_command, shell=True)

    def topUdpAllTcp(self):
        """topUdpAllTcp will run a full nmap tcp port scan and a top udp ports scan"""
        c = config_parser.CommandParser(f"{os.path.expanduser('~')}/.config/autorecon/config.yaml", self.target)
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        hpl = helper_lists.topPortsToScan()
        topUDP = hpl.topUDP
        topUdpPortsString = ",".join(map(str, topUDP))
        commands = []
        commands.append(c.getCmd("nmap", "nmapFullTcpScan"))
        commands.append(c.getCmd("nmap", "nmapTopUdpScan", topUdpPorts=topUdpPortsString))
        self.processes = tuple(commands)
