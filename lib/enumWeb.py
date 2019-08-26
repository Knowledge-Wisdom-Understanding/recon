#!/usr/bin/env python3

import os

# from multiprocessing import Pool
import time
from sty import fg, bg, ef, rs, RgbFg
from lib import nmapParser
import subprocess as s


class EnumWeb:
    def __init__(self, target):
        self.target = target
        self.processes = ""

    def Scan(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        http_ports = np.http_ports
        if len(http_ports) == 0:
            pass
        else:
            a = f"{fg.cyan} Enumerating HTTP Ports, Running the following commands: {fg.rs}"

            print(a)
            if not os.path.exists(f"{self.target}-Report/web"):
                os.makedirs(f"{self.target}-Report/web")
            http_string_ports = ",".join(map(str, http_ports))
            for port in http_ports:
                commands = (
                    f"whatweb -v -a 3 http://{self.target}:{port} >{self.target}-Report/web/whatweb-{self.target}-{port}.txt",
                    f"wafw00f http://{self.target}:{port} >{self.target}-Report/web/wafw00f-{self.target}-{port}.txt",
                    f"curl -sSik http://{self.target}:{port}/robots.txt -m 10 -o {self.target}-Report/web/robots-{self.target}-{port}.txt &>/dev/null",
                    f"python3 /opt/dirsearch/dirsearch.py -u http://{self.target}:{port} -t 50 -e php,asp,aspx,txt,html -x 403,500 -f --plain-text-report {self.target}-Report/web/dirsearch-{self.target}-{port}.log",
                    f"python3 /opt/dirsearch/dirsearch.py -u http://{self.target}:{port} -t 50 -e php,asp,aspx,txt,html -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x 403,500 --plain-text-report {self.target}-Report/web/dirsearch-dlistmedium-{self.target}-{port}.log",
                    f"nikto -ask=no -host http://{self.target}:{port} >{self.target}-Report/web/niktoscan-{self.target}-{port}.txt 2>&1 &",
                )
            self.processes = commands
            # print(self.processes)
