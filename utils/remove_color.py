#!/usr/bin/env python3

import re
from subprocess import call, PIPE
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
        awkprint = "{print $3}"
        awkprint2 = "{print $5}"
        dirsearch_files = []
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
                    if "dirsearch" in rf:
                        if not os.path.exists(f"{self.target}-Report/aquatone"):
                            os.makedirs(f"{self.target}-Report/aquatone")
                        dirsearch_files.append(rf)
                    if "aquatone" not in rf:
                        if "eyewitness" not in rf:
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
        if len(dirsearch_files) != 0:
            all_dirsearch_files_on_one_line = " ".join(map(str, dirsearch_files))
            url_list_cmd = f"""cat {all_dirsearch_files_on_one_line} | grep -v '400' | awk '{awkprint}' | sort -u > {cwd}/{self.target}-Report/aquatone/urls.txt"""
            call(url_list_cmd, shell=True)

