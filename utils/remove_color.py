#!/usr/bin/env python3

from subprocess import call, check_output, STDOUT
import os
import glob
from utils import config_parser
from fnmatch import fnmatch


class Clean:
    """The Clean Class is responsible for cleaning up output files that contain ANSI
    color codes. It's nice to have the color output in the terminal window, however, to
    avoid removing all color from the program, instead, I've created this helper class
    to remove all ANSI color codes from all color output found in the Report Results."""

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

        c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
        dir_list = [
            d
            for d in glob.iglob(c.getPath("report", "reportGlob"), recursive=True)
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
                                    self, rf, "/tmp/wafw00f.log"
                                )
                            if "whatweb" in rf:
                                removeColor(
                                    self, rf, "/tmp/whatweb.log"
                                )
                            if "sslscan" in rf:
                                removeColor(
                                    self,
                                    rf,
                                    "/tmp/sslscan.log",
                                )
                            if "dnsenum" in rf:
                                removeColor(
                                    self, rf, "/tmp/dnsenum.log"
                                )
                            if "drupal" in rf:
                                removeColor(
                                    self, rf, "/tmp/drupal.log"
                                )
                            if "oracle" in rf:
                                removeColor(
                                    self,
                                    rf,
                                    "/tmp/oracle-blah.log",
                                )
                                removeColor(
                                    self,
                                    rf,
                                    "/tmp/oracle-blah.log",
                                )
                            if "wpscan" in rf:
                                removeColor(
                                    self,
                                    rf,
                                    "/tmp/wpscanblah.log",
                                )
                            if "vulns" in rf:
                                if fnmatch(rf, "*.log"):
                                    removeColor(
                                        self,
                                        rf,
                                        "/tmp/doesntmatter.log",
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

        c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
        if os.path.exists(c.getPath("proxy", "proxyDir")):
            dir_list = [
                d
                for d in glob.iglob(c.getPath("proxy", "proxyGlob"), recursive=True)
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
                                        "/tmp/wafw00f.log",
                                    )
                                if "whatweb" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        "/tmp/whatweb.log",
                                    )
                                if "wpscan" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        "/tmp/wpscanblah.log",
                                    )
                                if "sslscan" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        "/tmp/sslscan.log",
                                    )
                                if "dnsenum" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        "/tmp/dnsenum.log",
                                    )
                                if "drupal" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        "/tmp/drupal.log",
                                    )
                                if "oracle" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        "/tmp/oracle-blah.log",
                                    )
                                if "oracle" in rf:
                                    removeColor(
                                        self,
                                        rf,
                                        "/tmp/oracleblah.log",
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
                                    if fnmatch(rf, "*.log"):
                                        removeColor(
                                            self,
                                            rf,
                                            "/tmp/doesntmatter.log",
                                        )
