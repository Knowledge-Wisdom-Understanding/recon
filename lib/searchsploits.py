#!/usr/bin/env python3

import os
from sty import fg, bg, ef, rs
from lib import nmapParser
from lib import brute
from subprocess import call
from utils import config_paths


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
        np.allOpenPorts()
        ftp_version = np.ftp_version
        ftp_product = np.ftp_product
        ssh_product = np.ssh_product
        ssh_version = np.ssh_version
        smtp_product = np.smtp_product
        smtp_version = np.smtp_version
        products = np.all_products
        http_title = np.http_script_title
        ignore = ["apache", "mysql"]
        c = config_paths.Configurator(self.target)
        c.createConfig()
        ### FTP searchsploit product ###
        if len(ftp_product) == 1:
            if not os.path.exists(f"""{c.getPath("vulnDir")}"""):
                os.makedirs(f"""{c.getPath("vulnDir")}""")
            string_ftp = " ".join(map(str, ftp_product))
            lowercase_string_ftp = str(string_ftp).lower()
            ftp_cmd = (
                f"""searchsploit {lowercase_string_ftp} > {c.getPath("ftp_vulns")}"""
            )
            print(cmd_info, ftp_cmd)
            call(ftp_cmd, shell=True)

        #### SSH searchsploit product ###
        if len(ssh_product) == 1:
            if not os.path.exists(f"""{c.getPath("vulnDir")}"""):
                os.makedirs(f"""{c.getPath("vulnDir")}""")
            string_ssh = " ".join(map(str, ssh_product))
            lowercase_string_ssh = str(string_ssh).lower()
            ssh_cmd = (
                f"""searchsploit {lowercase_string_ssh} > {c.getPath("ssh_vulns")}"""
            )
            print(cmd_info, ssh_cmd)
            call(ssh_cmd, shell=True)

        #### SMTP searchsploit product ###
        if len(smtp_product) == 1:
            if not os.path.exists(f"""{c.getPath("vulnDir")}"""):
                os.makedirs(f"""{c.getPath("vulnDir")}""")
            string_smtp = " ".join(map(str, smtp_product))
            lowercase_string_smtp = str(string_smtp).lower()
            smtp_cmd = (
                f"""searchsploit {lowercase_string_smtp} > {c.getPath("smtp_vulns")}"""
            )
            print(cmd_info, smtp_cmd)
            call(smtp_cmd, shell=True)

        #### HTTP Title searchsploit (hoping for CMS in title) ##########
        if len(http_title) >= 1:
            if not os.path.exists(f"""{c.getPath("vulnDir")}"""):
                os.makedirs(f"""{c.getPath("vulnDir")}""")
            if len(http_title) > 1:
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
                        http_cmd = f"""searchsploit {lowercase_title} >> {c.getPath("http_vulns")}"""
                        http_cmd2 = f"""searchsploit {first_word} >> {c.getPath("http_vulns")}"""
                        print(cmd_info, http_cmd)
                        print(cmd_info, http_cmd2)
                        call(http_cmd, shell=True)
                        call(http_cmd2, shell=True)

            else:
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
                    http_cmd = f"""searchsploit "{lowercase_title}" >> {c.getPath("http_vulns")}"""
                    http_cmd2 = (
                        f"""searchsploit "{first_word}" >> {c.getPath("http_vulns")}"""
                    )
                    print(cmd_info, http_cmd)
                    print(cmd_info, http_cmd2)
                    call(http_cmd, shell=True)
                    call(http_cmd2, shell=True)
        if len(products) != 0:
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
                        product_cmd = f"""echo "{cmd_info} {lowercase_product}" >> {c.getPath("all_vulns")}"""
                        product_cmd2 = f"""searchsploit "{lowercase_product}" >> {c.getPath("all_vulns")}"""
                        product_cmd3 = (
                            f"""echo "{cmd_info} {fw}" >> {c.getPath("all_vulns")}"""
                        )
                        product_cmd4 = (
                            f"""searchsploit "{fw}" >> {c.getPath("all_vulns")}"""
                        )
                        print(cmd_info, product_cmd2)
                        call(product_cmd, shell=True)
                        call(product_cmd2, shell=True)
                        call(product_cmd3, shell=True)
                        call(product_cmd4, shell=True)

    def vulnCheck(self):
        cmd_info = "[" + fg.green + "+" + fg.rs + "]"
        manual_cmd_info = "[" + fg.li_yellow + "+" + fg.rs + "]"
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
        c = config_paths.Configurator(self.target)
        c.createConfig()
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
                        f"""{cmd_info} {blue}{ssh_product[0]} {ssh_version[0]}{reset} is {red}vulnerable to username Enumeration{reset}"""
                    )
                    print(f"""{green}Consider running:{reset}""")
                    print(
                        f"""{manual_cmd_info} python {c.getPath("ssh_user_enum")} --port 22 --userList {c.getPath("usernames_wordlist")} {self.target} --outputFile {c.getPath("ssh_usernames")} --outputFormat json"""
                    )
                    # sb = brute.Brute(self.target, "ssh", ssh_port)
                    # sb.SshUsersBrute()
                else:
                    print(
                        f"""{cmd_info} {blue}{ssh_product[0]} {ssh_version[0]}{reset} is {red}NOT{reset} vulnerable to username Enumeration"""
                    )
