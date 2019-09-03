#!/usr/bin/env python3

from subprocess import call
import os
import glob


class Clean:
    def __init__(self, target):
        self.target = target

    def listfiles(self):
        """
        The Second Parameter for removeColor doesn't matter what the filename is
        as long as it's the correct path to where the files are that your
        removing ansi color codes from. The Remove color function removes ansi color
        codes from any matching files and essentially keeps the same name for the file
        by moving it to the temporary newfilename param and then moving it back to the
        filename param.
        This Class also creates the urls.txt file for aquatone from all the discovered links found from dirsearch.
        """

        def removeColor(self, filename, newfilename):
            sedCMD = f'sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" {filename} > {newfilename} && rm {filename} && mv {newfilename} {filename}'
            return call(sedCMD, shell=True)

        cwd = os.getcwd()
        reportPath = f"{cwd}/{self.target}-Report/*"
        awkprint = "{print $3}"
        dirsearch_files = []
        dir_list = [d for d in glob.iglob(f"{reportPath}", recursive=True) if os.path.isdir(d)]
        for d in dir_list:
            reportFile_list = [
                fname for fname in glob.iglob(f"{d}/*", recursive=True) if os.path.isfile(fname)
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
                                    self, rf, f"{os.getcwd()}/{self.target}-Report/web/wafw00f.txt"
                                )
                            if "whatweb" in rf:
                                removeColor(
                                    self, rf, f"{os.getcwd()}/{self.target}-Report/web/whatweb.txt"
                                )
                            if "sslscan" in rf:
                                removeColor(
                                    self,
                                    rf,
                                    f"{os.getcwd()}/{self.target}-Report/webSSL/sslscan.txt",
                                )
                            if "dnsenum" in rf:
                                removeColor(
                                    self, rf, f"{os.getcwd()}/{self.target}-Report/dns/dnsenum.log"
                                )
                            if "oracle" in rf:
                                removeColor(
                                    self,
                                    rf,
                                    f"{os.getcwd()}/{self.target}-Report/oracle/oracleblah.log",
                                )
                            if "nikto" in rf:
                                call(f"cat {rf}", shell=True)
                            if "vulns" in rf:
                                if "ftp" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        f"{os.getcwd()}/{self.target}-Report/vulns/ftpblah.log",
                                    )
                                if "ssh" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        f"{os.getcwd()}/{self.target}-Report/vulns/sshblah.log",
                                    )
                                if "smtp" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        f"{os.getcwd()}/{self.target}-Report/vulns/smtpblah.log",
                                    )
        if len(dirsearch_files) != 0:
            all_dirsearch_files_on_one_line = " ".join(map(str, dirsearch_files))
            url_list_cmd = f"""cat {all_dirsearch_files_on_one_line} | grep -v '400' | awk '{awkprint}' | sort -u > {cwd}/{self.target}-Report/aquatone/urls.txt"""
            call(url_list_cmd, shell=True)

