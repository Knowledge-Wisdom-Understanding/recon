#!/usr/bin/env python3

import os
from subprocess import call
from sty import fg, bg, ef, rs
from lib import nmapParser
import glob


class DefaultLinuxUsers:
    def __init__(self, target):
        self.target = target
        self.default_linux_users = [
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


class Cewl:
    def __init__(self, target):
        self.target = target

    def CewlWordlist(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        http_ports = np.http_ports
        htports = []
        if len(http_ports) == 1:
            htports.append(http_ports[0])
        ssl_ports = np.ssl_ports
        slports = []
        if len(ssl_ports) == 1:
            slports.append(ssl_ports[0])
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
                if len(htports) == 1:
                    url_list.append(f"http://{self.target}:{htports[0]}/")
                if len(slports) == 1:
                    url_list.append(f"https://{self.target}:{slports[0]}/")
                wordlist = sorted(set(url_list))
            except FileNotFoundError as fnf_error:
                print(fnf_error)
                exit()
            cewl_cmds = []
            if len(wordlist) != 0:
                counter = 0
                for url in wordlist:
                    counter += 1
                    cewl_cmds.append(
                        f"cewl {url} -m 3 -w {reportDir}/wordlists/cewl-{counter}-list.txt"
                    )
            if len(cewl_cmds) != 0:
                try:
                    for cmd in cewl_cmds:
                        call(cmd, shell=True)
                except ConnectionRefusedError as cre_error:
                    print(cre_error)
            words = []
            try:
                with open(f"{cwd}/wordlists/probable-v2-top1575.txt", "r") as prob:
                    for line in prob:
                        words.append(line.rstrip())
                for wl in os.listdir(f"{reportDir}/wordlists"):
                    wlfile = f"{reportDir}/wordlists/{wl}"
                    with open(wlfile, "r") as wlf:
                        for line in wlf:
                            words.append(line.rstrip())
                        set_unique_words = sorted(set(words))
                        unique_words = list(set_unique_words)
                        with open(f"{reportDir}/wordlists/all.txt", "a") as allwls:
                            string_words = "\n".join(map(str, unique_words))
                            allwls.write(str(string_words))
            except FileNotFoundError as fnf_error:
                print(fnf_error)


class Wordpress:
    def __init__(self, target):
        self.target = target
        self.wordpress_dirs = ["wordpress", "WordPress", "wp-content"]


class DirsearchURLS:
    def __init__(self, target):
        self.target = target

    def genDirsearchUrlList(self):
        cwd = os.getcwd()
        reportPath = f"{cwd}/{self.target}-Report/*"
        awkprint = "{print $3}"
        dirsearch_files = []
        dir_list = [d for d in glob.iglob(f"{reportPath}", recursive=True) if os.path.isdir(d)]
        for d in dir_list:
            reportFile_list = [
                fname for fname in glob.iglob(f"{d}/*", recursive=True) if os.path.isfile(fname)
            ]
            for rf in reportFile_list:
                if "nmap" not in rf:
                    if "dirsearch" in rf:
                        if not os.path.exists(f"{self.target}-Report/aquatone"):
                            os.makedirs(f"{self.target}-Report/aquatone")
                        dirsearch_files.append(rf)

        if len(dirsearch_files) != 0:
            all_dirsearch_files_on_one_line = " ".join(map(str, dirsearch_files))
            url_list_cmd = f"""cat {all_dirsearch_files_on_one_line} | grep -v '400' | awk '{awkprint}' | sort -u > {cwd}/{self.target}-Report/aquatone/urls.txt"""
            call(url_list_cmd, shell=True)

    def genProxyDirsearchUrlList(self):
        cwd = os.getcwd()
        if os.path.exists(f"{cwd}/{self.target}-Report/proxy"):
            reportPath = f"{cwd}/{self.target}-Report/proxy/*"
            awkprint = "{print $3}"
            dirsearch_files = []
            dir_list = [d for d in glob.iglob(f"{reportPath}", recursive=True) if os.path.isdir(d)]
            for d in dir_list:
                reportFile_list = [
                    fname for fname in glob.iglob(f"{d}/*", recursive=True) if os.path.isfile(fname)
                ]
                for rf in reportFile_list:
                    if "nmap" not in rf:
                        if "dirsearch" in rf:
                            if not os.path.exists(f"{self.target}-Report/aquatone"):
                                os.makedirs(f"{self.target}-Report/aquatone")
                            dirsearch_files.append(rf)

            if len(dirsearch_files) != 0:
                all_dirsearch_files_on_one_line = " ".join(map(str, dirsearch_files))
                url_list_cmd = f"""cat {all_dirsearch_files_on_one_line} | grep -v '400' | awk '{awkprint}' | sort -u > {cwd}/{self.target}-Report/aquatone/proxy-urls.txt"""
                call(url_list_cmd, shell=True)
