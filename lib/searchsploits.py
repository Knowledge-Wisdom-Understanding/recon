#!/usr/bin/env python3

import os
from sty import fg
from lib import nmapParser
from utils import config_parser
from heapq import merge
#from lib import brute


class Search:
    """The Search Class is responsible for running SearchSploit and checking for
    OpenSSH vulnerabilities, Specifically, Username Enumeration."""

    def __init__(self, target):
        self.target = target
        self.processes = ""
        self.versions = []
        self.ftp_info = []
        self.ssh_info = []
        self.smtp_info = []

    def Scan(self):
        """This Scan Funtion will take the parsed output from NmapParserFunk Class's output
        and attempt to run searchsploit against each service. Also, the HTTP-TITLE from nmap's
        script scans will be ran against searchsploit as oftentimes, a CMS's title may give away
        a vulnerable service or the CMS version itself."""
        ntop = nmapParser.NmapParserFunk(self.target)
        ntop.openPorts()
        np = nmapParser.NmapParserFunk(self.target)
        np.allOpenPorts()
        ftp_product = list(sorted(set(merge(ntop.ftp_product, np.ftp_product))))
        ssh_product = list(sorted(set(merge(ntop.ssh_product, np.ssh_product))))
        smtp_product = list(sorted(set(merge(ntop.smtp_product, np.smtp_product))))
        products = list(sorted(set(merge(ntop.all_products, np.all_products))))
        http_title = ntop.http_script_title
        ignore = ["apache", "mysql", "microsoft"]
        commands_to_run = []
        c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
        ### FTP searchsploit product ###
        if len(ftp_product) == 1:
            if not os.path.exists(c.getPath("vuln", "vulnDir")):
                os.makedirs(c.getPath("vuln", "vulnDir"))
            string_ftp = " ".join(map(str, ftp_product))
            lowercase_string_ftp = str(string_ftp).lower()
            ftp_cmd = c.getCmd("vuln", "searchsploit", strang=lowercase_string_ftp, name="ftp")
            commands_to_run.append(ftp_cmd)

        #### SSH searchsploit product ###
        if len(ssh_product) == 1:
            if not os.path.exists(c.getPath("vuln", "vulnDir")):
                os.makedirs(c.getPath("vuln", "vulnDir"))
            string_ssh = " ".join(map(str, ssh_product))
            lowercase_string_ssh = str(string_ssh).lower()
            ssh_cmd = c.getCmd("vuln", "searchsploit", strang=lowercase_string_ssh, name="ssh")
            commands_to_run.append(ssh_cmd)

        #### SMTP searchsploit product ###
        if len(smtp_product) == 1:
            if not os.path.exists(c.getPath("vuln", "vulnDir")):
                os.makedirs(c.getPath("vuln", "vulnDir"))
            string_smtp = " ".join(map(str, smtp_product))
            lowercase_string_smtp = str(string_smtp).lower()
            smtp_cmd = c.getCmd("vuln", "searchsploit", strang=lowercase_string_smtp, name="smtp")
            commands_to_run.append(smtp_cmd)

        #### HTTP Title searchsploit (hoping for CMS in title) ##########
        if len(http_title) >= 1:
            if not os.path.exists(c.getPath("vuln", "vulnDir")):
                os.makedirs(c.getPath("vuln", "vulnDir"))
            if len(http_title) > 1:
                if not os.path.exists(c.getPath("vuln", "vulnDir")):
                    os.makedirs(c.getPath("vuln", "vulnDir"))
                for title in http_title:
                    string_title = " ".join(map(str, title))
                    lowercase_title = str(string_title).lower()
                    if lowercase_title.find("redirect") != -1:
                        pass
                    elif lowercase_title.find("site doesn't have a title") != -1:
                        pass
                    elif lowercase_title.find("apache2") != -1:
                        pass
                    elif lowercase_title.find("nginx") != -1:
                        pass
                    else:
                        first_word = lowercase_title.split(" ", 1)[0]
                        first_two_words = " ".join(lowercase_title.replace("[", "").replace("]", "").replace("\n", " ").replace("'", "").split(" ", 2)[0:2])
                        http_cmd = c.getCmd("vuln", "searchsploit", strang=str(first_two_words), name="http-title")
                        http_cmd2 = c.getCmd("vuln", "searchsploit", strang=first_word, name=f"{first_word}")
                        commands_to_run.append(http_cmd)
                        commands_to_run.append(http_cmd2)

            else:
                if not os.path.exists(c.getPath("vuln", "vulnDir")):
                    os.makedirs(c.getPath("vuln", "vulnDir"))
                string_title = " ".join(map(str, http_title))
                lowercase_title = str(string_title).lower()
                if lowercase_title.find("redirect") != -1:
                    pass
                elif lowercase_title.find("site doesn't have a title") != -1:
                    pass
                elif lowercase_title.find("apache2") != -1:
                    pass
                elif lowercase_title.find("nginx") != -1:
                    pass
                else:
                    first_word = lowercase_title.split(" ", 1)[0]
                    first_two_words = " ".join(lowercase_title.replace("[", "").replace("]", "").replace("\n", " ").replace("'", "").split(" ", 2)[0:2])
                    http_cmd = c.getCmd("vuln", "searchsploit", strang=str(first_two_words), name="http-title")
                    http_cmd2 = c.getCmd("vuln", "searchsploit", strang=first_word, name=f"{first_word}")
                    commands_to_run.append(http_cmd)
                    commands_to_run.append(http_cmd2)
        if len(products) != 0:
            if not os.path.exists(c.getPath("vuln", "vulnDir")):
                os.makedirs(c.getPath("vuln", "vulnDir"))
            for p in products:
                lowercase_product = str(p).lower()
                fw = lowercase_product.split(" ", 1)[0]
                if not lowercase_product:
                    pass
                if not fw:
                    pass
                else:
                    if lowercase_product in ignore:
                        pass
                    if fw in ignore:
                        pass
                    else:
                        product_cmd2 = c.getCmd("vuln", "searchsploit", strang=lowercase_product, name="all-services")
                        product_cmd4 = c.getCmd("vuln", "searchsploit", strang=str(fw), name="all-services")
                        commands_to_run.append(product_cmd2)
                        commands_to_run.append(product_cmd4)

        sorted_cmds = sorted(set(commands_to_run))
        commands_to_run = [i for i in sorted_cmds]
        self.processes = tuple(commands_to_run)
        if len(commands_to_run) != 0:
            print(f"[{fg.li_yellow}+{fg.rs}] {fg.li_cyan}SEARCHING FOR EXPLOITS {fg.rs}")

    def vulnCheck(self):
        """Vuln Check will check if OpenSSH is vulnerable to Username Enumeration.
        If it is, A message will be printed to the User. This feature can be enabled to automatically
        always brute force SSH if the instance is a vulnerable version, however, I've changed this
        feature to not run automatically as that option should be left up to the user, among various other
        reasons."""
        cmd_info = "[" + fg.green + "+" + fg.rs + "]"
        manual_cmd_info = "[" + fg.li_yellow + "+" + fg.rs + "]"
        blue = fg.li_blue
        red = fg.red
        green = fg.li_green
        reset = fg.rs
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        ssh_product = np.ssh_product
        ssh_version = np.ssh_version
        c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
        # Check what version OPENSSH is
        # If OpenSSH version is less than 7.7, Enumerate Users
        # If valid Unique User is found, Brute Force Passwords
        if len(ssh_product) == 1:
            if ssh_version is not None:
                string_ssh_version = " ".join(map(str, ssh_version))
                if len(string_ssh_version) >= 2:
                    lowercase_ssh_version = str(string_ssh_version).lower()
                    first_two_nums = lowercase_ssh_version[0:3]
                    int_first_two_nums = float(first_two_nums)
                    if ssh_product[0] == "OpenSSH":
                        if int_first_two_nums < float(7.7):
                            ssh_port = np.ssh_ports
                            print(f"""{cmd_info} {blue}{ssh_product[0]} {ssh_version[0]}{reset} is {red}VULNERABLE to Username Enumeration{reset}""")
                            print(f"""{green}Consider running:{reset}""")
                            print(f"""{manual_cmd_info} {c.getCmd("ssh", "ssh_user_enum", port=ssh_port[0])}""")
                            # sb = brute.Brute(self.target, "ssh", ssh_port)
                            # sb.SshUsersBrute()
                        else:
                            print(f"""{cmd_info} {blue}{ssh_product[0]} {ssh_version[0]}{reset} is {red}NOT{reset} Vulnerable to Username Enumeration""")
