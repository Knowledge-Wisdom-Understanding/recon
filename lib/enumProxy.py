#!/usr/bin/env python3

import os
from sys import exit
from subprocess import call
import re
from sty import fg, bg, ef, rs, RgbFg
from lib import nmapParser
from lib import enumWeb
from lib import enumWebSSL


class CheckProxy:
    def __init__(self, target):
        self.target = target
        self.all_processes = ""

    def Scan(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        proxyPorts = np.proxy_ports
        cwd = os.getcwd()
        cmd_info = "[" + fg.li_green + "+" + fg.rs + "]"
        if len(proxyPorts) == 0:
            pass
        else:
            duplicate_cmds = []
            add_line_cmd = f"""sed -e "\$ahttp {self.target} {proxyPorts[0]}" -i /etc/proxychains.conf"""
            proxy_config_file = "/etc/proxychains.conf"
            try:
                pcCF = open(proxy_config_file, "r")
                for line in pcCF:
                    parsed_lines = (
                        line.replace("#", "")
                        .replace("socks4 ", "")
                        .replace("socks5 ", "")
                        .replace("http ", "")
                    )
                matches = re.findall(self.target, parsed_lines)
                sorted_matches = sorted(set(matches), reverse=True)
                if self.target not in sorted_matches:
                    duplicate_cmds.append(add_line_cmd)
                pcCF.close()
                sorted_cmds = sorted(set(duplicate_cmds))
                if len(sorted_cmds) == 1:
                    call(sorted_cmds[0], shell=True)
            except FileNotFoundError as fnf_error:
                print(fnf_error)
                exit()

            if not os.path.exists(f"{self.target}-Report/proxy"):
                os.makedirs(f"{self.target}-Report/proxy")

            proxychains_nmap_top_ports_cmd = f"proxychains nmap -vv -sT -Pn -sV -T3 --max-retries 1 --max-scan-delay 20 --top-ports 10000 -oA {self.target}-Report/nmap/proxychain-top-ports 127.0.0.1"
            print(cmd_info, proxychains_nmap_top_ports_cmd)
            call(proxychains_nmap_top_ports_cmd, shell=True)

    def Enum(self):
        npp = nmapParser.NmapParserFunk(self.target)
        npp.openProxyPorts()
        open_proxy_ports = npp.proxy_ports2
        if len(open_proxy_ports) == 0:
            pass
        else:
            pweb = enumWeb.EnumWeb(self.target)
            pweb.proxyScan()
            http_proxy_commands = pweb.proxy_processes
            psslweb = enumWebSSL.EnumWebSSL(self.target)
            psslweb.sslProxyScan()
            ssl_proxy_commands = psslweb.proxy_processes
            all_commands = []
            proxy_tcp_ports = npp.proxy_tcp_ports
            tcp_proxy_ports = ",".join(map(str, proxy_tcp_ports))
            default_command = f"proxychains nmap -vv -sT -Pn -sC -sV -p {tcp_proxy_ports} --script-timeout 2m -oA {self.target}-Report/nmap/proxychain-ServiceScan 127.0.0.1"
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
