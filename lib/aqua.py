#!/usr/bin/env python3

import os
from sty import fg, bg, ef, rs, RgbFg
from lib import nmapParser
from subprocess import call


class Aquatone:
    def __init__(self, target):
        self.target = target

    def Scan(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
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
            aquatone_cmd = f"""cat {urls_path} | aquatone -ports {all_web_ports_comma_list} -out {aqua_path} -screenshot-timeout 40000"""
            call(aquatone_cmd, shell=True)

