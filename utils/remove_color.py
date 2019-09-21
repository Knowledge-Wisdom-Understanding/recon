#!/usr/bin/env python3

from subprocess import call, check_output, STDOUT
import os
import glob
from utils import config_paths


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

        c = config_paths.Configurator(self.target)
        c.createConfig()
        dir_list = [
            d
            for d in glob.iglob(f"""{c.getPath("reportGlob")}""", recursive=True)
            if os.path.isdir(d)
        ]
        for d in dir_list:
            reportFile_list = [
                fname
                for fname in glob.iglob(f"{d}/*", recursive=True)
                if os.path.isfile(fname)
            ]
            for rf in reportFile_list:
                if "nmap" not in rf:
                    if "aquatone" not in rf:
                        if "eyewitness" not in rf:
                            if "wafw00f" in rf:
                                removeColor(
                                    self, rf, f"""{c.getPath("webDir")}/wafw00f.txt"""
                                )
                            if "whatweb" in rf:
                                removeColor(
                                    self, rf, f"""{c.getPath("webDir")}/whatweb.txt"""
                                )
                            if "sslscan" in rf:
                                removeColor(
                                    self,
                                    rf,
                                    f"""{c.getPath("webSSLDir")}/sslscan.txt""",
                                )
                            if "dnsenum" in rf:
                                removeColor(
                                    self, rf, f"""{c.getPath("dnsDir")}/dnsenum.log"""
                                )
                            if "oracle" in rf:
                                removeColor(
                                    self,
                                    rf,
                                    f"""{c.getPath("oracleDir")}/oracleblah.log""",
                                )
                            if "wpscan" in rf:
                                removeColor(
                                    self,
                                    rf,
                                    f"""{c.getPath("webDir")}/wpscanblah.log""",
                                )
                            if "vulns" in rf:
                                if "ftp" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        f"""{c.getPath("vulnDir")}/ftpblah.log""",
                                    )
                                if "ssh" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        f"""{c.getPath("vulnDir")}/sshblah.log""",
                                    )
                                if "smtp" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        f"""{c.getPath("vulnDir")}/smtpblah.log""",
                                    )
                                if "http" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        f"""{c.getPath("vulnDir")}/http-title-blah.log""",
                                    )
                                if "https" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        f"""{c.getPath("vulnDir")}/https-title-blah.log""",
                                    )
                                if "all-services" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        f"""{c.getPath("vulnDir")}/all-services-blah.log""",
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

        c = config_paths.Configurator(self.target)
        c.createConfig()
        if os.path.exists(f"""{c.getPath("proxyDir")}"""):
            dir_list = [
                d
                for d in glob.iglob(f"""{c.getPath("proxyGlob")}""", recursive=True)
                if os.path.isdir(d)
            ]
            for d in dir_list:
                reportFile_list = [
                    fname
                    for fname in glob.iglob(f"{d}/*", recursive=True)
                    if os.path.isfile(fname)
                ]
                for rf in reportFile_list:
                    if "nmap" not in rf:
                        if "aquatone" not in rf:
                            if "eyewitness" not in rf:
                                if "wafw00f" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        f"""{c.getPath("proxyWeb")}/wafw00f.txt""",
                                    )
                                if "whatweb" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        f"""{c.getPath("proxyWeb")}/whatweb.txt""",
                                    )
                                if "wpscan" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        f"""{c.getPath("proxyWeb")}/wpscanblah.txt""",
                                    )
                                if "sslscan" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        f"""{c.getPath("proxyWebSSL")}/sslscan.txt""",
                                    )
                                if "dnsenum" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        f"""{c.getPath("proxyDns")}/dnsenum.log""",
                                    )
                                if "oracle" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        f"""{c.getPath("proxyOracle")}/oracleblah.log""",
                                    )
                                if "nikto" in rf:
                                    check_nikto_lines = (
                                        f"""wc -l {rf} | cut -d ' ' -f 1"""
                                    )
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
                                            f"""{c.getPath("proxyVulns")}/ftpblah.log""",
                                        )
                                    if "ssh" in rf:
                                        removeColor(
                                            self,
                                            rf,
                                            f"""{c.getPath("proxyVulns")}/sshblah.log""",
                                        )
                                    if "smtp" in rf:
                                        removeColor(
                                            self,
                                            rf,
                                            f"""{c.getPath("proxyVulns")}/smtpblah.log""",
                                        )
                                    if "http" in rf:
                                        removeColor(
                                            self,
                                            rf,
                                            f"""{c.getPath("proxyVulns")}/http-title-blah.log""",
                                        )
                                    if "https" in rf:
                                        removeColor(
                                            self,
                                            rf,
                                            f"""{c.getPath("proxyVulns")}/https-title-blah.log""",
                                        )
