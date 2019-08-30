#!/usr/bin/env python3

import os
from sty import fg, bg, ef, rs, RgbFg
from lib import nmapParser
from subprocess import call, check_output, STDOUT
from shutil import which
import sys


class Aquatone:
    def __init__(self, target):
        self.target = target

    def Scan(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        cwd = os.getcwd()
        cmd_info = "[" + fg.li_green + "+" + fg.rs + "]"
        ssl_ports = np.ssl_ports
        http_ports = np.http_ports
        all_web_ports = []
        for x in ssl_ports:
            all_web_ports.append(x)
        for x in http_ports:
            all_web_ports.append(x)
        all_web_ports_comma_list = ",".join(map(str, all_web_ports))
        cwd = os.getcwd()
        if not os.path.exists(f"{self.target}-Report/aquatone"):
            os.makedirs(f"{self.target}-Report/aquatone")
        b = fg.cyan + "Opening Aquatone Report" + fg.rs
        urls_path = f"{cwd}/{self.target}-Report/aquatone/urls.txt"
        aqua_path = f"{cwd}/{self.target}-Report/aquatone/aquatone"
        if os.path.exists(urls_path):
            check_lines = f"""wc -l {urls_path} | cut -d ' ' -f 1"""
            num_urls = check_output(check_lines, stderr=STDOUT, shell=True).rstrip()
            ### ToDo: open urls.txt and sort urls by occurance of response codes.
            if int(num_urls) < 50:
                aquatone_cmd = f"""cat {urls_path} | aquatone -ports {all_web_ports_comma_list} -out {aqua_path} -screenshot-timeout 40000"""
                print(cmd_info, aquatone_cmd)
                call(aquatone_cmd, shell=True)
                if not which("firefox"):
                    pass
                else:
                    os.path.exists(
                        f"{cwd}/{self.target}-Report/aquatone/aquatone/aquatone_report.html"
                    )
                    open_in_ff_cmd = f"firefox {cwd}/{self.target}-Report/aquatone/aquatone/aquatone_report.html &"
                    call(open_in_ff_cmd, shell=True)
