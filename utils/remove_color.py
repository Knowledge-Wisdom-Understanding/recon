#!/usr/bin/env python3

from subprocess import call, check_output, STDOUT
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
        dir_list = [d for d in glob.iglob(f"{reportPath}", recursive=True) if os.path.isdir(d)]
        for d in dir_list:
            reportFile_list = [
                fname for fname in glob.iglob(f"{d}/*", recursive=True) if os.path.isfile(fname)
            ]
            for rf in reportFile_list:
                if "nmap" not in rf:
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
                            if "wpscan" in rf:
                                removeColor(
                                    self,
                                    rf,
                                    f"{os.getcwd()}/{self.target}-Report/web/wpscanblah.log",
                                )
                            if "nikto" in rf:
                                check_nikto_lines = f"""wc -l {rf} | cut -d ' ' -f 1"""
                                num_lines_nikto = check_output(
                                    check_nikto_lines, stderr=STDOUT, shell=True
                                ).rstrip()
                                if int(num_lines_nikto) < 50:
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
                                if "http" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        f"{os.getcwd()}/{self.target}-Report/vulns/http-title-blah.log",
                                    )
                                if "https" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        f"{os.getcwd()}/{self.target}-Report/vulns/https-title-blah.log",
                                    )

    def listFilesProxy(self):
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
        if os.path.exists(f"{cwd}/{self.target}-Report/proxy"):
            reportPath = f"{cwd}/{self.target}-Report/proxy/*"
            dir_list = [d for d in glob.iglob(f"{reportPath}", recursive=True) if os.path.isdir(d)]
            for d in dir_list:
                reportFile_list = [
                    fname for fname in glob.iglob(f"{d}/*", recursive=True) if os.path.isfile(fname)
                ]
                for rf in reportFile_list:
                    if "nmap" not in rf:
                        if "aquatone" not in rf:
                            if "eyewitness" not in rf:
                                if "wafw00f" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        f"{os.getcwd()}/{self.target}-Report/proxy/web/wafw00f.txt",
                                    )
                                if "whatweb" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        f"{os.getcwd()}/{self.target}-Report/proxy/web/whatweb.txt",
                                    )
                                if "wpscan" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        f"{os.getcwd()}/{self.target}-Report/proxy/web/wpscanblah.txt",
                                    )
                                if "sslscan" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        f"{os.getcwd()}/{self.target}-Report/proxy/webSSL/sslscan.txt",
                                    )
                                if "dnsenum" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        f"{os.getcwd()}/{self.target}-Report/proxy/dns/dnsenum.log",
                                    )
                                if "oracle" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        f"{os.getcwd()}/{self.target}-Report/proxy/oracle/oracleblah.log",
                                    )
                                if "nikto" in rf:
                                    check_nikto_lines = f"""wc -l {rf} | cut -d ' ' -f 1"""
                                    num_lines_nikto = check_output(
                                        check_nikto_lines, stderr=STDOUT, shell=True
                                    ).rstrip()
                                    if int(num_lines_nikto) < 50:
                                        call(f"cat {rf}", shell=True)
                                if "vulns" in rf:
                                    if "ftp" in rf:
                                        removeColor(
                                            self,
                                            rf,
                                            f"{os.getcwd()}/{self.target}-Report/proxy/vulns/ftpblah.log",
                                        )
                                    if "ssh" in rf:
                                        removeColor(
                                            self,
                                            rf,
                                            f"{os.getcwd()}/{self.target}-Report/proxy/vulns/sshblah.log",
                                        )
                                    if "smtp" in rf:
                                        removeColor(
                                            self,
                                            rf,
                                            f"{os.getcwd()}/{self.target}-Report/proxy/vulns/smtpblah.log",
                                        )
                                    if "http" in rf:
                                        removeColor(
                                            self,
                                            rf,
                                            f"{os.getcwd()}/{self.target}-Report/proxy/vulns/http-title-blah.log",
                                        )
                                    if "https" in rf:
                                        removeColor(
                                            self,
                                            rf,
                                            f"{os.getcwd()}/{self.target}-Report/proxy/vulns/https-title-blah.log",
                                        )
