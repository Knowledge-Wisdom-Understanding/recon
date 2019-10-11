#!/usr/bin/env python3

import os
from subprocess import call
import re
from sty import fg
from lib import nmapParser
from lib import enumWeb
from lib import enumWebSSL
from utils import helper_lists
from utils import config_parser


class CheckProxy:
    """The CheckProxy Class will Attempt to run a nmap scan using proxychains if any valid
    http-proxy ports are found to be open from nmap's initial scanning results from the NmapParserFunk class
    located in lib/nmapParser.py"""

    def __init__(self, target):
        self.target = target
        self.all_processes = ""

    def Scan(self):
        """If there is an open http-proxy port from nmaps results. Try to add the server IP to your proxychains
        config file and then proceed to scan the target again through the proxy port using proxychains and nmap.
        If more ports are discovered open, proceed to enumerate all found open ports through the http-proxy port."""
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        proxyPorts = np.proxy_ports
        hpl = helper_lists.topPortsToScan()
        topTCP = hpl.topTCP
        topTcpPortsString = ",".join(map(str, topTCP))
        cmd_info = "[" + fg.li_green + "+" + fg.rs + "]"
        if len(proxyPorts) == 0:
            pass
        else:
            c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
            duplicate_cmds = []
            add_line_cmd = rf"""sed -e "\$ahttp {self.target} {proxyPorts[0]}" -i /etc/proxychains.conf"""
            comment_out_line_cmd = (
                f"""sed -e '/socks5/ s/^#*/#/' -i  /etc/proxychains.conf"""
            )
            proxy_config_file = "/etc/proxychains.conf"
            try:
                pcCF = open(proxy_config_file, "r")
                for line in pcCF:
                    parsed_lines = line.rstrip()
                    if not parsed_lines.startswith("#"):
                        tor_match = re.findall("socks5", parsed_lines)
                        sorted_tor_matches = sorted(set(tor_match), reverse=True)
                        if "socks5" in sorted_tor_matches:
                            duplicate_cmds.append(comment_out_line_cmd)
                if (parsed_lines.startswith("#") or not parsed_lines.startswith('#')):
                    matches = re.findall(f"http {self.target}", parsed_lines)
                    sorted_matches = sorted(set(matches), reverse=True)
                    if f"http {self.target}" not in sorted_matches:
                        duplicate_cmds.append(add_line_cmd)
                pcCF.close()
                sorted_cmds = sorted(set(duplicate_cmds))
                if len(sorted_cmds) != 0:
                    for cmd in sorted_cmds:
                        call(cmd, shell=True)
            except FileNotFoundError as fnf_error:
                print(fnf_error)
                exit()

            if not os.path.exists(c.getPath("proxy", "proxyDir")):
                os.makedirs(c.getPath("proxy", "proxyDir"))

            proxychains_nmap_top_ports_cmd = c.getCmd("proxy", "proxychainsNmapTopPorts", topTcpPorts=topTcpPortsString)
            print(cmd_info, proxychains_nmap_top_ports_cmd)
            call(proxychains_nmap_top_ports_cmd, shell=True)

    def Enum(self):
        """This is a helper function that will run all the Enumeration Commands Based off of nmaps proxychain original output scan if new ports are discovered."""
        npp = nmapParser.NmapParserFunk(self.target)
        npp.openProxyPorts()
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        open_proxy_ports = np.proxy_ports
        if len(open_proxy_ports) == 0:
            pass
        else:
            c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
            pweb = enumWeb.EnumWeb(self.target)
            pweb.proxyScan()
            http_proxy_commands = pweb.proxy_processes
            psslweb = enumWebSSL.EnumWebSSL(self.target)
            psslweb.sslProxyScan()
            ssl_proxy_commands = psslweb.proxy_processes
            all_commands = []
            proxy_tcp_ports = npp.proxy_tcp_ports
            tcp_proxy_ports = ",".join(map(str, proxy_tcp_ports))
            default_command = c.getCmd("proxy", "proxychainsDiscoveredPorts", openTcpProxyPorts=tcp_proxy_ports)
            all_commands.append(default_command)
            for cmd in http_proxy_commands:
                all_commands.append(cmd)
            for cmd in ssl_proxy_commands:
                all_commands.append(cmd)
            sorted_commands = sorted(set(all_commands), reverse=True)
            commands_to_run = []
            for i in sorted_commands:
                commands_to_run.append(i)
            allCmds = tuple(commands_to_run)
            self.all_processes = allCmds
