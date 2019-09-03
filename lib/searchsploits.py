#!/usr/bin/env python3

import os
from sty import fg, bg, ef, rs
from lib import nmapParser
from subprocess import call


class Search:
    def __init__(self, target):
        self.target = target
        self.processes = ""
        self.versions = []
        self.ftp_info = []
        self.ssh_info = []
        self.smtp_info = []

    def Scan(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        ftp_version = np.ftp_version
        ssh_version = np.ssh_version
        smtp_version = np.smtp_version
        ### FTP get product info ###
        if len(ftp_version) == 1:
            ftp_dict = {}
            for b in ftp_version:
                i = b.split(": ")
                ftp_dict[i[0]] = i[1].replace(" version", "")
            self.ftp_info.append(ftp_dict["product"])
        ### SSH get product info ###
        if len(ssh_version) == 1:
            ssh_dict = {}
            for b in ssh_version:
                i = b.split(": ")
                ssh_dict[i[0]] = i[1].replace(" version", "")
            self.ssh_info.append(ssh_dict["product"])
        ### SMTP get product info ###
        if len(smtp_version) == 1:
            smtp_dict = {}
            for b in smtp_version:
                i = b.split(": ")
                smtp_dict[i[0]] = i[1].replace(" version", "")
            self.ssh_info.append(smtp_dict["product"])

    def Sploits(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        ftp_version = np.ftp_version
        ssh_version = np.ssh_version
        smtp_version = np.smtp_version
        if len(ftp_version) == 1:
            if not os.path.exists(f"{self.target}-Report/vulns"):
                os.makedirs(f"{self.target}-Report/vulns")
            string_ftp = " ".join(map(str, self.ftp_info)).replace(",", "")
            lowercase_string_ftp = str(string_ftp).lower()
            ftp_cmd = f"searchsploit {lowercase_string_ftp} > {self.target}-Report/vulns/ftp.log"
            call(ftp_cmd, shell=True)
        if len(ssh_version) == 1:
            if not os.path.exists(f"{self.target}-Report/vulns"):
                os.makedirs(f"{self.target}-Report/vulns")
            string_ssh = " ".join(map(str, self.ssh_info)).replace(",", "")
            lowercase_string_ssh = str(string_ssh).lower()
            ssh_cmd = f"searchsploit {lowercase_string_ssh} > {self.target}-Report/vulns/ssh.log"
            call(ssh_cmd, shell=True)
        if len(smtp_version) == 1:
            if not os.path.exists(f"{self.target}-Report/vulns"):
                os.makedirs(f"{self.target}-Report/vulns")
            string_smtp = " ".join(map(str, self.smtp_info)).replace(",", "")
            lowercase_string_smtp = str(string_smtp).lower()
            smtp_cmd = f"searchsploit {lowercase_string_smtp} > {self.target}-Report/vulns/smtp.log"
            call(smtp_cmd, shell=True)

