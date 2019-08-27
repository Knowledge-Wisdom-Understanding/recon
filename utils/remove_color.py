#!/usr/bin/env python3

import re
from subprocess import call
import os
import glob


class Clean:
    def __init__(self, target):
        self.target = target

    def listfiles(self):
        def removeColor(self, filename, newfilename):
            sedCMD = f'sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" {filename} > {newfilename} && rm {filename} && mv {newfilename} {filename}'
            return call(sedCMD, shell=True)

        cwd = os.getcwd()
        reportPath = f"{cwd}/{self.target}-Report/*"
        dir_list = [
            d for d in glob.iglob(f"{reportPath}", recursive=True) if os.path.isdir(d)
        ]
        for d in dir_list:
            reportFile_list = [
                fname
                for fname in glob.iglob(f"{d}/*", recursive=True)
                if os.path.isfile(fname)
            ]
            for rf in reportFile_list:
                if "nmap" not in rf:
                    if "wafw00f" in rf:
                        removeColor(
                            self,
                            rf,
                            f"{os.getcwd()}/{self.target}-Report/web/wafw00f.txt",
                        )
                    if "whatweb" in rf:
                        removeColor(
                            self,
                            rf,
                            f"{os.getcwd()}/{self.target}-Report/web/whatweb.txt",
                        )
                    if "sslscan" in rf:
                        removeColor(
                            self,
                            rf,
                            f"{os.getcwd()}/{self.target}-Report/web/sslscan.txt",
                        )
                    if "dnsenum" in rf:
                        removeColor(
                            self,
                            rf,
                            f"{os.getcwd()}/{self.target}-Report/dns/dnsenum.log",
                        )
