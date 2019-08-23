#!/usr/bin/env python3

import os
import subprocess as s


class EnumServices:
    def __init__(self, cats, target):
        # self.service = service
        # self.httpPorts = httpPorts
        # self.sslPorts = sslPorts
        # self.smbPorts = smbPorts
        self.cats = cats
        self.target = target

    def Scan(self):
        print("printing contents of ports to stdout")
        cwd_path = os.path.dirname(os.path.realpath(__file__))
        self.cats = s.call("cat " + cwd_path + "ports.txt")
        print("target IP is: " + self.target)
