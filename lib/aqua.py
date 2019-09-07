#!/usr/bin/env python3

import os
from sty import fg, bg, ef, rs
from lib import nmapParser
from subprocess import call, check_output, STDOUT
from shutil import which


class Aquatone:
    def __init__(self, target):
        self.target = target

    def Scan(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        npp = nmapParser.NmapParserFunk(self.target)
        npp.openProxyPorts()
        cwd = os.getcwd()
        cmd_info = "[" + fg.li_green + "+" + fg.rs + "]"
        ssl_ports = np.ssl_ports
        http_ports = np.http_ports
        proxy_http_ports = npp.proxy_http_ports
        proxy_ssl_ports = npp.proxy_ssl_ports
        proxy_ports = np.proxy_ports
        all_web_ports = []
        all_web_proxy_ports = []
        for x in ssl_ports:
            all_web_ports.append(x)
        for x in http_ports:
            all_web_ports.append(x)
        for x in proxy_http_ports:
            all_web_proxy_ports.append(x)
        for x in proxy_ssl_ports:
            all_web_proxy_ports.append(x)
        all_web_ports_comma_list = ",".join(map(str, all_web_ports))
        all_web_proxy_ports_comma_list = ",".join(map(str, all_web_proxy_ports))
        cwd = os.getcwd()
        if not os.path.exists(f"{self.target}-Report/aquatone"):
            os.makedirs(f"{self.target}-Report/aquatone")
        urls_path = f"{cwd}/{self.target}-Report/aquatone/urls.txt"
        proxy_urls_path = f"{cwd}/{self.target}-Report/aquatone/proxy-urls.txt"
        aqua_path = f"{cwd}/{self.target}-Report/aquatone/aquatone"
        aqua_proxy_path = f"{cwd}/{self.target}-Report/aquatone/aquatone-proxy"
        if os.path.exists(urls_path):
            check_lines = f"""wc -l {urls_path} | cut -d ' ' -f 1"""
            num_urls = check_output(check_lines, stderr=STDOUT, shell=True).rstrip()
            ### ToDo: open urls.txt and sort urls by occurance of response codes.
            if int(num_urls) < 100:
                aquatone_cmd = f"""cat {urls_path} | aquatone -ports {all_web_ports_comma_list} -out {aqua_path} -screenshot-timeout 40000"""
                print(cmd_info, aquatone_cmd)
                call(aquatone_cmd, shell=True)
                if not which("firefox"):
                    pass
                else:
                    if os.path.exists(
                        f"{cwd}/{self.target}-Report/aquatone/aquatone/aquatone_report.html"
                    ):
                        print(f"{fg.cyan}Opening Aquatone Report {fg.rs}")
                        open_in_ff_cmd = f"firefox {cwd}/{self.target}-Report/aquatone/aquatone/aquatone_report.html &"
                        call(open_in_ff_cmd, shell=True)
        if os.path.exists(proxy_urls_path):
            check_lines = f"""wc -l {proxy_urls_path} | cut -d ' ' -f 1"""
            num_urls = check_output(check_lines, stderr=STDOUT, shell=True).rstrip()
            if int(num_urls) < 100:
                aquatone_cmd = f"""cat {proxy_urls_path} | aquatone -ports {all_web_proxy_ports_comma_list} -proxy http://{self.target}:{proxy_ports[0]} -out {aqua_proxy_path} -screenshot-timeout 40000"""
                print(cmd_info, aquatone_cmd)
                call(aquatone_cmd, shell=True)
                if not which("firefox"):
                    pass
                else:
                    if os.path.exists(
                        f"{cwd}/{self.target}-Report/aquatone/aquatone-proxy/aquatone_report.html"
                    ):
                        open_in_ff_proxy_cmd = f"firefox {cwd}/{self.target}-Report/aquatone/aquatone-proxy/aquatone_report.html &"
                        call(open_in_ff_proxy_cmd, shell=True)

