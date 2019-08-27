#!/usr/bin/env python3

import os
import subprocess as s
from sty import fg, bg, ef, rs, RgbFg
from lib import nmapParser

# import sys


class CheckProxy:
    def __init__(self, target):
        self.target = target

    def Scan(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        proxyPorts = np.proxy_ports
        if len(proxyPorts) == 0:
            pass
        else:
            if not os.path.exists(f"{self.target}-Report/proxy"):
                os.makedirs(f"{self.target}-Report/proxy")
            if not os.path.exists(f"{self.target}-Report/aquatone"):
                os.makedirs(f"{self.target}-Report/aquatone")
            c = (
                fg.cyan
                + "Enumerating HTTP-PROXY : Running the following commands:"
                + fg.rs
            )
            print(c)
