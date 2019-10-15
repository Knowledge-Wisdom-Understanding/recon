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
        This function will list all files in report output folder and remove ansi color codes from the file
        using sed.
        """

        def removeColor(self, filename):
            sedCMD = rf'sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" -i {filename}'
            return call(sedCMD, shell=True)

        c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
        dir_list = [d for d in glob.iglob(c.getPath("report", "reportGlob"), recursive=True) if os.path.isdir(d)]
        for d in dir_list:
            reportFile_list = [fname for fname in glob.iglob(f"{d}/*", recursive=True) if os.path.isfile(fname)]
            for rf in reportFile_list:
                if "nmap" not in rf:
                    if "aquatone" not in rf:
                        if "eyewitness" not in rf:
                            if "wafw00f" in rf:
                                removeColor(self, rf)
                            if "whatweb" in rf:
                                removeColor(self, rf)
                            if "sslscan" in rf:
                                removeColor(self, rf)
                            if "dnsenum" in rf:
                                removeColor(self, rf)
                            if "drupal" in rf:
                                removeColor(self, rf)
                            if "joomlavs" in rf:
                                removeColor(self, rf)
                            if "oracle" in rf:
                                removeColor(self, rf)
                            if "wpscan" in rf:
                                removeColor(self, rf)
                            if "vulns" in rf:
                                if fnmatch(rf, "*.log"):
                                    removeColor(self, rf)

    def listFilesProxy(self):
        """
        This function will list all files in report output folder and remove ansi color codes from the file
        using sed. It will also display niktos output if the latter was ran.
        """

        def removeColor(self, filename):
            sedCMD = rf'sed "s,\x1B\[[0-9;]*[a-zA-Z],,g" -i {filename}'
            return call(sedCMD, shell=True)

        c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
        if os.path.exists(c.getPath("proxy", "proxyDir")):
            dir_list = [d for d in glob.iglob(c.getPath("proxy", "proxyGlob"), recursive=True) if os.path.isdir(d)]
            for d in dir_list:
                reportFile_list = [fname for fname in glob.iglob(f"{d}/*", recursive=True) if os.path.isfile(fname)]
                for rf in reportFile_list:
                    if "nmap" not in rf:
                        if "aquatone" not in rf:
                            if "eyewitness" not in rf:
                                if "wafw00f" in rf:
                                    removeColor(self, rf)
                                if "whatweb" in rf:
                                    removeColor(self, rf)
                                if "wpscan" in rf:
                                    removeColor(self, rf)
                                if "sslscan" in rf:
                                    removeColor(self, rf)
                                if "dnsenum" in rf:
                                    removeColor(self, rf)
                                if "drupal" in rf:
                                    removeColor(self, rf)
                                if "joomlavs" in rf:
                                    removeColor(self, rf)
                                if "oracle" in rf:
                                    removeColor(self, rf)
                                if "oracle" in rf:
                                    removeColor(self, rf)
                                if "nikto" in rf:
                                    check_nikto_lines = (f"""wc -l {rf} | cut -d ' ' -f 1""")
                                    num_lines_nikto = check_output(check_nikto_lines, stderr=STDOUT, shell=True).rstrip()
                                    if int(num_lines_nikto) < 80:
                                        call(f"cat {rf}", shell=True)
                                if "vulns" in rf:
                                    if fnmatch(rf, "*.log"):
                                        removeColor(self, rf)
