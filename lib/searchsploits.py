#!/usr/bin/env python3

import os
from sty import fg, bg, ef, rs
from lib import nmapParser
from lib import brute
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
        cmd_info = "[" + fg.green + "+" + fg.rs + "]"
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        ftp_version = np.ftp_version
        ftp_product = np.ftp_product
        ssh_product = np.ssh_product
        ssh_version = np.ssh_version
        smtp_product = np.smtp_product
        smtp_version = np.smtp_version
        http_title = np.http_script_title

        ### FTP searchsploit product ###
        if len(ftp_product) == 1:
            if not os.path.exists(f"{self.target}-Report/vulns"):
                os.makedirs(f"{self.target}-Report/vulns")
            string_ftp = " ".join(map(str, ftp_product))
            lowercase_string_ftp = str(string_ftp).lower()
            ftp_cmd = f"searchsploit {lowercase_string_ftp} > {self.target}-Report/vulns/ftp.log"
            print(cmd_info, ftp_cmd)
            call(ftp_cmd, shell=True)

        #### SSH searchsploit product ###
        if len(ssh_product) == 1:
            if not os.path.exists(f"{self.target}-Report/vulns"):
                os.makedirs(f"{self.target}-Report/vulns")
            string_ssh = " ".join(map(str, ssh_product))
            lowercase_string_ssh = str(string_ssh).lower()
            ssh_cmd = f"searchsploit {lowercase_string_ssh} > {self.target}-Report/vulns/ssh.log"
            print(cmd_info, ssh_cmd)
            call(ssh_cmd, shell=True)

        #### SMTP searchsploit product ###
        if len(smtp_product) == 1:
            if not os.path.exists(f"{self.target}-Report/vulns"):
                os.makedirs(f"{self.target}-Report/vulns")
            string_smtp = " ".join(map(str, smtp_product))
            lowercase_string_smtp = str(string_smtp).lower()
            smtp_cmd = f"searchsploit {lowercase_string_smtp} > {self.target}-Report/vulns/smtp.log"
            print(cmd_info, smtp_cmd)
            call(smtp_cmd, shell=True)

        #### HTTP Title searchsploit (hoping for CMS in title) ##########
        if len(http_title) >= 1:
            if not os.path.exists(f"{self.target}-Report/vulns"):
                os.makedirs(f"{self.target}-Report/vulns")
            if len(http_title) > 1:
                for title in http_title:
                    string_title = " ".join(map(str, title))
                    lowercase_title = str(string_title).lower()
                    first_word = lowercase_title.split(" ", 1)[0]
                    http_cmd = f"searchsploit {lowercase_title} >> {self.target}-Report/vulns/http-title.log"
                    http_cmd2 = (
                        f"searchsploit {first_word} >> {self.target}-Report/vulns/http-title.log"
                    )
                    print(cmd_info, http_cmd)
                    print(cmd_info, http_cmd2)
                    call(http_cmd, shell=True)
                    call(http_cmd2, shell=True)

            else:
                string_title = " ".join(map(str, http_title))
                lowercase_title = str(string_title).lower()
                first_word = lowercase_title.split(" ", 1)[0]
                http_cmd = (
                    f"searchsploit {lowercase_title} >> {self.target}-Report/vulns/http-title.log"
                )
                http_cmd2 = (
                    f"searchsploit {first_word} >> {self.target}-Report/vulns/http-title.log"
                )
                print(cmd_info, http_cmd)
                print(cmd_info, http_cmd2)
                call(http_cmd, shell=True)
                call(http_cmd2, shell=True)

    def vulnCheck(self):
        cmd_info = "[" + fg.green + "+" + fg.rs + "]"
        blue = fg.li_blue
        red = fg.red
        green = fg.li_green
        reset = fg.rs
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        ftp_version = np.ftp_version
        ftp_product = np.ftp_product
        ssh_product = np.ssh_product
        ssh_version = np.ssh_version
        smtp_product = np.smtp_product
        smtp_version = np.smtp_version

        ## Check what version OPENSSH is
        ## If OpenSSH version is less than 7.7, Enumerate Users
        ## If valid Unique User is found, Brute Force Passwords
        if len(ssh_product) == 1:
            string_ssh_version = " ".join(map(str, ssh_version))
            lowercase_ssh_version = str(string_ssh_version).lower()
            first_two_nums = lowercase_ssh_version[0:3]
            int_first_two_nums = float(first_two_nums)
            if ssh_product[0] == "OpenSSH":
                if int_first_two_nums < float(7.7):
                    ssh_port = np.ssh_ports[0]
                    print(
                        f"{cmd_info} {blue}{ssh_product[0]} {ssh_version[0]}{reset} is {red}vulnerable to username Enumeration{reset}"
                    )
                    print(f"{green}Running SSH User Enumeration !!!{reset}")
                    sb = brute.Brute(self.target, "ssh", ssh_port)
                    sb.SshUsersBrute()
                else:
                    print(
                        f"{cmd_info} {blue}{ssh_product[0]} {ssh_version[0]}{reset} is {red}NOT{reset} vulnerable to username Enumeration"
                    )
