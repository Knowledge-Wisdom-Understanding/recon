#!/usr/bin/env python3

import os
from sty import fg
from autorecon.lib import nmapParser, ldap_imp
from autorecon.lib import domainFinder
from autorecon.utils import config_parser
import re
from subprocess import call, PIPE, Popen
import requests
from autorecon.utils import helper_lists
from collections.abc import Iterable


class KerbEnum:
    """KerbEnum Will Enumerate kerberos usernames etc.."""

    def __init__(self, target):
        self.target = target
        self.processes = ""
        self.ldapper = ldap_imp.enumLdap(self.target)

    def PwnWinRM(self):

        c = config_parser.CommandParser(f"{os.path.expanduser('~')}/.config/autorecon/config.yaml", self.target)
        if not os.path.exists(c.getPath("kerberos", "kerbDir")):
            os.makedirs(c.getPath("kerberos", "kerbDir"))

        def parse_users():
            """
            Returns a list of users
            """
            if os.path.exists(c.getPath("kerberos", "kerbUsers")):
                with open(c.getPath("kerberos", "kerbUsers"), 'r') as kbu:
                    users = [u.split()[6].split('@')[0] for u in kbu.readlines() if 'VALID USERNAME:' in u]
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

        def check_parse_hashes():
            print(f"[{fg.li_magenta}+{fg.rs}] Creating List of Valid Usernames")
            users = parse_users()
            print(f"[{fg.li_green}+{fg.rs}] Checking for Kerberos Pre-Authentication TGT Hashes")
            domain = self.ldapper.get_domain()
            hashes = []
            if domain and users:
                for u in users:
                    try:
                        hashes.append(self.ldapper.get_tgt(u))
                    except Exception as e:
                        print(e)
                if hashes:
                    print(f"Found tgt hashes {hashes}")
                if not os.path.exists(c.getPath("loot", "lootDir")):
                    os.makedirs(c.getPath("loot", "lootDir"))
                with open(c.getPath("loot", "krbHashes"), "w") as hash_file:
                    if hashes:
                        for i in hashes:
                            hash_file.write(i.rstrip() + "\n")
            return hashes

        def KerbBrute():
            domain = parse_ad_domain()
            if domain:
                dope_cmd = f"""{c.getCmd("kerberos", "kerbrute", domain=str(domain[0]))}"""
                print(f"[{fg.li_magenta}+{fg.rs}] {dope_cmd}")
                call(dope_cmd, shell=True)
                users = parse_users()
                if users:
                    print(users)
                    print("Todo: finish this module...")

        KerbBrute()
