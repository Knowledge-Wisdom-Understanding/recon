#!/usr/bin/env python3

import os
from sty import fg, bg, ef, rs
from lib import nmapParser
from lib import dnsenum
import glob
from utils import config_paths
from subprocess import call


class EnumWebSSL:
    """EnumWebSSL will Enumerate all Found SSL/HTTPS webservers with open ports from the nmapParser. The following tools
    are described in this Classes Scan() function."""

    def __init__(self, target):
        self.target = target
        self.processes = ""
        self.proxy_processes = ""
        self.cms_processes = ""

    def Scan(self):
        """Enumerate HTTPS/SSL Web Server ports based on nmaps output. This function will run the following tools;
        WhatWeb, WafW00f, Dirsearch, EyeWitness, Nikto, and curl robots.txt"""
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        df = dnsenum.DnsEnum(self.target)
        df.GetHostNames()
        hostnames = df.hostnames
        ssl_ports = np.ssl_ports
        if len(ssl_ports) == 0:
            pass
        else:
            green = fg.li_green
            reset = fg.rs
            cmd_info = "[" + green + "+" + reset + "]"
            c = config_paths.Configurator(self.target)
            c.createConfig()
            c.cmdConfig()
            if not os.path.exists(f"""{c.getPath("webSSLDir")}"""):
                os.makedirs(f"""{c.getPath("webSSLDir")}""")
            if not os.path.exists(f"""{c.getPath("aquatoneDir")}"""):
                os.makedirs(f"""{c.getPath("aquatoneDir")}""")
            print(
                fg.li_cyan
                + "Enumerating HTTPS/SSL Ports, Running the following commands:"
                + fg.rs
            )
            commands = ()
            if len(hostnames) == 0:
                for sslport in ssl_ports:
                    commands = commands + (
                        f"""echo {cmd_info} {green} '{c.getCmd("whatwebSSLt")}:{sslport} | tee {c.getPath("webSSLWhatWebT")}-{sslport}.txt' {reset}""",
                        f"""{c.getCmd("whatwebSSLt")}:{sslport} | tee {c.getPath("webSSLWhatWebT")}-{sslport}.txt""",
                        f"""echo {cmd_info} {green} 'wafw00f https://{self.target}:{sslport} >{c.getPath("webSSLwafw00fT")}-{sslport}.txt' {reset}""",
                        f"""wafw00f https://{self.target}:{sslport} >{c.getPath("webSSLwafw00fT")}-{sslport}.txt""",
                        f"""echo {cmd_info} {green} 'curl -sSik https://{self.target}:{sslport}/robots.txt -m 10 -o {c.getPath("webSSLRobotsT")}-{sslport}.txt &>/dev/null' {reset}""",
                        f"""curl -sSik https://{self.target}:{sslport}/robots.txt -m 10 -o {c.getPath("webSSLRobotsT")}-{sslport}.txt &>/dev/null""",
                        f"""echo {cmd_info} {green} '{c.getCmd("dirsearchSSLTarget")}:{sslport}/ -t 30 -e {c.getCmd("ext")} -x {c.getCmd("hc")} -w {c.getPath("wlDict")} --plain-text-report {c.getPath("webSSLDirsearchT")}-{sslport}.log' {reset}""",
                        f"""{c.getCmd("dirsearchSSLTarget")}:{sslport}/ -t 30 -e {c.getCmd("ext")} -x {c.getCmd("hc")} -w {c.getPath("wlDict")} --plain-text-report {c.getPath("webSSLDirsearchT")}-{sslport}.log""",
                        f"""echo {cmd_info} {green} '{c.getCmd("dirsearchSSLTarget")}:{sslport}/ -t 80 -e {c.getCmd("ext")} -w {c.getPath("Big")} -x {c.getCmd("hc")} --plain-text-report {c.getPath("webSSLDirsearchBigT")}-{sslport}.log' {reset}""",
                        f"""{c.getCmd("dirsearchSSLTarget")}:{sslport}/ -t 80 -e {c.getCmd("ext")} -w {c.getPath("Big")} -x {c.getCmd("hc")} --plain-text-report {c.getPath("webSSLDirsearchBigT")}-{sslport}.log""",
                        f"""echo {cmd_info} {green} 'nikto -ask=no -host https://{self.target}:{sslport} -ssl  >{c.getPath("webSSLNiktoT")}-{sslport}.txt 2>&1 &' {reset}""",
                        f"""nikto -ask=no -host https://{self.target}:{sslport} -ssl  >{c.getPath("webSSLNiktoT")}-{sslport}.txt 2>&1 &""",
                    )
            else:
                for sslport in ssl_ports:
                    for host in hostnames:
                        commands = commands + (
                            f"""echo {cmd_info} {green} '{c.getCmd("whatwebSSL")}{host}:{sslport} >{c.getPath("webSSLWhatWeb")}-{host}-{sslport}.txt' {reset}""",
                            f"""{c.getCmd("whatwebSSL")}{host}:{sslport} >{c.getPath("webSSLWhatWeb")}-{host}-{sslport}.txt""",
                            f"""echo {cmd_info} {green} 'wafw00f https://{host}:{sslport} >{c.getPath("webSSLwafw00f")}-{host}-{sslport}.txt' {reset}""",
                            f"""wafw00f https://{host}:{sslport} >{c.getPath("webSSLwafw00f")}-{host}-{sslport}.txt""",
                            f"""echo {cmd_info} {green} 'curl -sSik https://{host}:{sslport}/robots.txt -m 10 -o {c.getPath("webSSLRobots")}-{host}-{sslport}.txt &>/dev/null' {reset}""",
                            f"""curl -sSik https://{host}:{sslport}/robots.txt -m 10 -o {c.getPath("webSSLRobots")}-{host}-{sslport}.txt &>/dev/null""",
                            f"""echo {cmd_info} {green} '{c.getCmd("dirsearchSSL")}{host}:{sslport}/ -t 50 -e {c.getCmd("ext")} -x {c.getCmd("hc")} --plain-text-report {c.getPath("webSSLDirsearch")}-{host}-{sslport}.log' {reset}""",
                            f"""{c.getCmd("dirsearchSSL")}{host}:{sslport}/ -t 50 -e {c.getCmd("ext")} -x {c.getCmd("hc")} --plain-text-report {c.getPath("webSSLDirsearch")}-{host}-{sslport}.log""",
                            f"""echo {cmd_info} {green} '{c.getCmd("dirsearchSSL")}{host}:{sslport}/ -t 50 -e {c.getCmd("ext")} -w {c.getPath("Big")} -x {c.getCmd("ext")} --plain-text-report {c.getPath("webSSLDirsearchBig")}-{host}-{sslport}.log' {reset}""",
                            f"""{c.getCmd("dirsearchSSL")}{host}:{sslport}/ -t 50 -e {c.getCmd("ext")} -w {c.getPath("Big")} -x {c.getCmd("ext")} --plain-text-report {c.getPath("webSSLDirsearchBig")}-{host}-{sslport}.log""",
                            f"""echo {cmd_info} {green} 'nikto -ask=no -host https://{host}:{sslport} -ssl  >{c.getPath("webSSLNikto")}-{host}-{sslport}.txt 2>&1 &' {reset}""",
                            f"""nikto -ask=no -host https://{host}:{sslport} -ssl  >{c.getPath("webSSLNikto")}-{host}-{sslport}.txt 2>&1 &""",
                        )

            self.processes = commands

    def ScanWebOption(self):
        """Enumerate Web Server ports based on nmaps output. This function will run the following tools;
        WhatWeb, WafW00f, Dirsearch, EyeWitness, Nikto, and curl robots.txt
        This is almost identical to the normal web scan except, it uses much larger wordlists
         and doesn't run EyeWitnesss Since that tool is run on the intended default
        Original Scan option."""
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        df = dnsenum.DnsEnum(self.target)
        df.GetHostNames()
        hostnames = df.hostnames
        ssl_ports = np.ssl_ports
        if len(ssl_ports) == 0:
            pass
        else:
            green = fg.li_green
            reset = fg.rs
            cmd_info = "[" + green + "+" + reset + "]"
            c = config_paths.Configurator(self.target)
            c.createConfig()
            c.cmdConfig()
            if not os.path.exists(f"""{c.getPath("webSSLDir")}"""):
                os.makedirs(f"""{c.getPath("webSSLDir")}""")
            if not os.path.exists(f"""{c.getPath("aquatoneDir")}"""):
                os.makedirs(f"""{c.getPath("aquatoneDir")}""")
            print(
                fg.li_cyan
                + "Enumerating HTTPS/SSL Ports, Running the following commands:"
                + fg.rs
            )
            if len(hostnames) == 0:
                for sslport in ssl_ports:
                    commands = (
                        f"""echo {cmd_info} {green} 'whatweb -v -a 3 https://{self.target}:{sslport} | tee {c.getPath("webSSLWhatWebT")}-{sslport}.txt' {reset}""",
                        f"""whatweb -v -a 3 https://{self.target}:{sslport} | tee {c.getPath("webSSLWhatWebT")}-{sslport}.txt""",
                        f"""echo {cmd_info} {green} 'wafw00f https://{self.target}:{sslport} >{c.getPath("webSSLwafw00fT")}-{sslport}.txt' {reset}""",
                        f"""wafw00f https://{self.target}:{sslport} >{c.getPath("webSSLwafw00fT")}-{sslport}.txt""",
                        f"""echo {cmd_info} {green} 'curl -sSik https://{self.target}:{sslport}/robots.txt -m 10 -o {c.getPath("webSSLRobotsT")}-{sslport}.txt &>/dev/null' {reset}""",
                        f"""curl -sSik https://{self.target}:{sslport}/robots.txt -m 10 -o {c.getPath("webSSLRobotsT")}-{sslport}.txt &>/dev/null""",
                        f"""echo {cmd_info} {green} '{c.getCmd("dirsearchSSLT")}:{sslport} -t 80 -e {c.getCmd("ext")} -w {c.getPath("dlistMed")} -x {c.getCmd("hc")} --plain-text-report {c.getPath("webSSLDirsearchDLMT")}-{sslport}.log' {reset}""",
                        f"""{c.getCmd("dirsearchSSLT")}:{sslport} -t 80 -e {c.getCmd("ext")} -w {c.getPath("dlistMed")} -x {c.getCmd("hc")} --plain-text-report {c.getPath("webSSLDirsearchDLMT")}-{sslport}.log""",
                        f"""echo {cmd_info} {green} '{c.getCmd("dirsearchSSLT")}:{sslport} -t 50 -e {c.getCmd("ext2")} -x {c.getCmd("hc")} -w {c.getPath("raftLarge")} --plain-text-report {c.getPath("webSSLDirsearchRFT")}-{sslport}.log' {reset}""",
                        f"""{c.getCmd("dirsearchSSLT")}:{sslport} -t 50 -e {c.getCmd("ext2")} -x {c.getCmd("hc")} -w {c.getPath("raftLarge")} --plain-text-report {c.getPath("webSSLDirsearchRFT")}-{sslport}.log""",
                        f"""echo {cmd_info} {green} '{c.getCmd("dirsearchSSLT")}:{sslport} -t 50 -e {c.getCmd("ext")} -x {c.getCmd("hc")} -w {c.getPath("raftLd")} --plain-text-report {c.getPath("webSSLDirsearchRLDT")}-{sslport}.log' {reset}""",
                        f"""{c.getCmd("dirsearchSSLT")}:{sslport} -t 50 -e {c.getCmd("ext")} -x {c.getCmd("hc")} -w {c.getPath("raftLd")} --plain-text-report {c.getPath("webSSLDirsearchRLDT")}-{sslport}.log""",
                        f"""echo {cmd_info} {green} '{c.getCmd("dirsearchSSLT")}:{sslport} -t 50 -e {c.getCmd("ext")} -w wordlists/foreign.txt -x {c.getCmd("hc")} --plain-text-report {c.getPath("webSSLDirsearchFT")}-{sslport}.log' {reset}""",
                        f"""{c.getCmd("dirsearchSSLT")}:{sslport} -t 50 -e {c.getCmd("ext")} -w wordlists/foreign.txt -x {c.getCmd("hc")} --plain-text-report {c.getPath("webSSLDirsearchFT")}-{sslport}.log""",
                        f"""echo {cmd_info} {green} 'nikto -ask=no -host https://{self.target}:{sslport} -ssl  >{c.getPath("webSSLNiktoT")}-{sslport}.txt 2>&1 &' {reset}""",
                        f"""nikto -ask=no -host https://{self.target}:{sslport} -ssl  >{c.getPath("webSSLNiktoT")}-{sslport}.txt 2>&1 &""",
                    )
            else:
                for ssl_port2 in ssl_ports:
                    commands = ()
                    for i in hostnames:
                        commands = commands + (
                            f"""echo {cmd_info} {green} 'whatweb -v -a 3 https://{i}:{ssl_port2} >{self.target}-Report/webSSL/whatweb-{i}-{ssl_port2}.txt' {reset}""",
                            f"""whatweb -v -a 3 https://{i}:{ssl_port2} >{self.target}-Report/webSSL/whatweb-{i}-{ssl_port2}.txt""",
                            f"""echo {cmd_info} {green} 'wafw00f https://{i}:{ssl_port2} >{self.target}-Report/webSSL/wafw00f-{i}-{ssl_port2}.txt' {reset}""",
                            f"""wafw00f https://{i}:{ssl_port2} >{self.target}-Report/webSSL/wafw00f-{i}-{ssl_port2}.txt""",
                            f"""echo {cmd_info} {green} 'curl -sSik https://{i}:{ssl_port2}/robots.txt -m 10 -o {c.getPath("webSSLRobots")}-{i}-{ssl_port2}.txt &>/dev/null' {reset}""",
                            f"""curl -sSik https://{i}:{ssl_port2}/robots.txt -m 10 -o {c.getPath("webSSLRobots")}-{i}-{ssl_port2}.txt &>/dev/null""",
                            f"""echo {cmd_info} {green} '{c.getCmd("dirsearchSSL")}{i}:{ssl_port2} -t 50 -e {c.getCmd("ext2")} -x {c.getCmd("hc")} -w {c.getPath("raftLarge")} --plain-text-report {c.getPath("webSSLDirsearchRF")}-{i}-{ssl_port2}.log' {reset}""",
                            f"""{c.getCmd("dirsearchSSL")}{i}:{ssl_port2} -t 50 -e {c.getCmd("ext2")} -x {c.getCmd("hc")} -w {c.getPath("raftLarge")} --plain-text-report {c.getPath("webSSLDirsearchRF")}-{i}-{ssl_port2}.log""",
                            f"""echo {cmd_info} {green} '{c.getCmd("dirsearchSSL")}{i}:{ssl_port2} -t 50 -e {c.getCmd("ext")} -w {c.getPath("dlistMed")} -x {c.getCmd("hc")} --plain-text-report {c.getPath("webSSLDirsearchDLM")}-{i}-{ssl_port2}.log' {reset}""",
                            f"""{c.getCmd("dirsearchSSL")}{i}:{ssl_port2} -t 50 -e {c.getCmd("ext")} -w {c.getPath("dlistMed")} -x {c.getCmd("hc")} --plain-text-report {c.getPath("webSSLDirsearchDLM")}-{i}-{ssl_port2}.log""",
                            f"""echo {cmd_info} {green} '{c.getCmd("dirsearchSSL")}{i}:{ssl_port2} -t 50 -e {c.getCmd("ext")} -w wordlists/foreign.txt -x {c.getCmd("hc")} --plain-text-report {c.getPath("webSSLDirsearchF")}-{i}-{ssl_port2}.log' {reset}""",
                            f"""{c.getCmd("dirsearchSSL")}{i}:{ssl_port2} -t 50 -e {c.getCmd("ext")} -w wordlists/foreign.txt -x {c.getCmd("hc")} --plain-text-report {c.getPath("webSSLDirsearchF")}-{i}-{ssl_port2}.log""",
                            f"""echo {cmd_info} {green} '{c.getCmd("dirsearchSSL")}{i}:{ssl_port2} -t 50 -e {c.getCmd("ext")} -x {c.getCmd("hc")} -w {c.getPath("raftLd")} --plain-text-report {c.getPath("webSSLDirsearchRLD")}-{i}-{ssl_port2}.log' {reset}""",
                            f"""{c.getCmd("dirsearchSSL")}{i}:{ssl_port2} -t 50 -e {c.getCmd("ext")} -x {c.getCmd("hc")} -w {c.getPath("raftLd")} --plain-text-report {c.getPath("webSSLDirsearchRLD")}-{i}-{ssl_port2}.log""",
                            f"""echo {cmd_info} {green} 'nikto -ask=no -host https://{i}:{ssl_port2} -ssl  >{c.getPath("webSSLNikto")}-{i}-{ssl_port2}.txt 2>&1 &' {reset}""",
                            f"""nikto -ask=no -host https://{i}:{ssl_port2} -ssl  >{c.getPath("webSSLNikto")}-{i}-{ssl_port2}.txt 2>&1 &""",
                        )

            self.processes = commands

    def sslProxyScan(self):
        """This function is called by lib/enumProxy.py and will enumerate HTTPS/SSL Web Servers.
        It will run, whatweb, dirsearch, and nikto."""
        npp = nmapParser.NmapParserFunk(self.target)
        npp.openProxyPorts()
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        proxy_ssl_ports = npp.proxy_ssl_ports
        proxy_ports = np.proxy_ports
        if len(proxy_ssl_ports) == 0:
            pass
        else:
            green = fg.li_green
            reset = fg.rs
            cmd_info = "[" + green + "+" + reset + "]"
            c = config_paths.Configurator(self.target)
            c.createConfig()
            c.cmdConfig()
            if not os.path.exists(f"""{c.getPath("proxyDir")}"""):
                os.makedirs(f"""{c.getPath("proxyDir")}""")
            if not os.path.exists(f"""{c.getPath("proxyWebSSL")}"""):
                os.makedirs(f"""{c.getPath("proxyWebSSL")}""")
            proxy_commands = ()
            for proxy in proxy_ports:
                print(
                    f"""{fg.li_cyan} Enumerating HTTPS Ports Through {proxy}, Running the following commands: {fg.rs}"""
                )
                for proxy_ssl_port in proxy_ssl_ports:
                    proxy_commands = proxy_commands + (
                        f"""echo {cmd_info} {green} 'whatweb -v -a 3 --proxy {self.target}:{proxy} https://127.0.0.1:{proxy_ssl_port} | tee {self.target}-Report/proxy/webSSL/whatweb-proxy-{self.target}-{proxy_ssl_port}.txt' {reset}""",
                        f"""whatweb -v -a 3 --proxy {self.target}:{proxy} https://127.0.0.1:{proxy_ssl_port} | tee {self.target}-Report/proxy/webSSL/whatweb-proxy-{self.target}-{proxy_ssl_port}.txt""",
                        f"""echo {cmd_info} {green} '{c.getCmd("dirsearchProxyT")}:{proxy} -u https://127.0.0.1:{proxy_ssl_port} --plain-text-report {c.getPath("webSSLDirsearchPT")}-{proxy}-{proxy_ssl_port}.log' {reset}""",
                        f"""{c.getCmd("dirsearchProxyT")}:{proxy} -u https://127.0.0.1:{proxy_ssl_port} --plain-text-report {c.getPath("webSSLDirsearchPT")}-{proxy}-{proxy_ssl_port}.log""",
                        f"""echo {cmd_info} {green} '{c.getCmd("dirsearchE")} {c.getCmd("ext")} -x {c.getCmd("hc")} -t 50 -w {c.getCmd("Big")} --proxy {self.target}:{proxy} -u https://127.0.0.1:{proxy_ssl_port} --plain-text-report {c.getPath("webSSLDirsearchPTB")}-{proxy}-{proxy_ssl_port}.log' {reset}""",
                        f"""{c.getCmd("dirsearchE")} {c.getCmd("ext")} -x {c.getCmd("hc")} -t 50 -w {c.getCmd("Big")} --proxy {self.target}:{proxy} -u https://127.0.0.1:{proxy_ssl_port} --plain-text-report {c.getPath("webSSLDirsearchPTB")}-{proxy}-{proxy_ssl_port}.log""",
                        f"""echo {cmd_info} {green} 'nikto -ask=no -host https://127.0.0.1:{proxy_ssl_port}/ -ssl -useproxy https://{self.target}:{proxy}/ > {self.target}-Report/proxy/webSSL/nikto-{self.target}-{proxy_ssl_port}-proxy-scan.txt 2>&1 &' {reset}""",
                        f"""nikto -ask=no -host https://127.0.0.1:{proxy_ssl_port}/ -ssl -useproxy https://{self.target}:{proxy}/ > {self.target}-Report/proxy/webSSL/nikto-{self.target}-{proxy_ssl_port}-proxy-scan.txt 2>&1 &""",
                    )

            self.proxy_processes = proxy_commands
            # print(self.processes)

    def sslEnumCMS(self):
        """If a valid CMS is found from initial Web Enumeration, more specifically, WhatWebs results, Then proceed to 
        Enumerate the CMS further using Wpscan, Magescan, Nmap, Droopescan, Joomscan, and davtest, hydra, and will
        create a brute force bash script using Cewl, which will then be used by WpScan to try and brute force
        Users and passwords."""
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        df = dnsenum.DnsEnum(self.target)
        df.GetHostNames()
        hostnames = df.hostnames
        ssl_ports = np.ssl_ports
        cms_commands = []
        if len(ssl_ports) == 0:
            pass
        else:
            c = config_paths.Configurator(self.target)
            c.createConfig()
            c.cmdConfig()
            for ssl_port in ssl_ports:
                whatweb_files = []
                whatweb_hostnames = []
                dir_list = [
                    d
                    for d in glob.iglob(
                        f"""{c.getPath("reportGlobWebSSL")}""", recursive=True
                    )
                    if os.path.isdir(d)
                ]
                for d in dir_list:
                    reportFile_list = [
                        fname
                        for fname in glob.iglob(f"""{d}/*""", recursive=True)
                        if os.path.isfile(fname)
                    ]
                    for rf in reportFile_list:
                        if "nmap" not in rf:
                            if "whatweb" in rf:
                                if ssl_port in rf:
                                    whatweb_files.append(rf)
                                if len(hostnames) != 0:
                                    for host in hostnames:
                                        if host in rf:
                                            whatweb_hostnames.append(rf)
                if len(whatweb_files) != 0:
                    for i in whatweb_files:
                        cms_strings = [
                            "WordPress",
                            "Magento",
                            "tomcat",
                            "WebDAV",
                            "Drupal",
                            "Joomla",
                        ]
                        with open(i, "r") as wwf:
                            for word in wwf:
                                fword = (
                                    word.replace("[", " ")
                                    .replace("]", " ")
                                    .replace(",", " ")
                                )
                                for cms in cms_strings:
                                    if cms in fword:
                                        if len(whatweb_hostnames) == 0:
                                            if "WordPress" in cms:
                                                wpscan_cmd = f"""wpscan --no-update --disable-tls-checks --url https://{self.target}:{ssl_port}/ --wp-content-dir wp-content --enumerate vp,vt,cb,dbe,u,m --plugins-detection aggressive | tee {c.getPath("reportDir")}/webSSL/wpscan-{ssl_port}.log"""
                                                cms_commands.append(wpscan_cmd)
                                                manual_brute_force_script = f"""
#!/bin/bash

if [[ -n $(grep -i "User(s) Identified" {c.getPath("reportDir")}/webSSL/wpscan-{ssl_port}.log) ]]; then
    grep -w -A 100 "User(s)" {c.getPath("reportDir")}/webSSL/wpscan-{ssl_port}.log | grep -w "[+]" | cut -d " " -f 2 | head -n -7 >{c.getPath("reportDir")}/webSSL/wp-users.txt
    cewl https://{self.target}:{ssl_port}/ -m 3 -w {c.getPath("reportDir")}/webSSL/cewl-list.txt
    sleep 10
    echo "Adding John Rules to Cewl Wordlist!"
    john --rules --wordlist={c.getPath("reportDir")}/webSSL/cewl-list.txt --stdout >{c.getPath("reportDir")}/webSSL/john-cool-list.txt
    sleep 3
    # brute force again with wpscan
    wpscan --no-update --disable-tls-checks --url https://{self.target}:{ssl_port}/ --wp-content-dir wp-login.php -U {c.getPath("reportDir")}/webSSL/wp-users.txt -P {c.getPath("reportDir")}/webSSL/cewl-list.txt threads 50 | tee {c.getPath("reportDir")}/webSSL/wordpress-cewl-brute.txt
    sleep 1
    if grep -i "No Valid Passwords Found" {c.getPath("reportDir")}/webSSL/wordpress-cewl-brute.txt; then
        if [ -s {c.getPath("reportDir")}/webSSL/john-cool-list.txt ]; then
            wpscan --no-update --disable-tls-checks --url https://{self.target}:{ssl_port}/ --wp-content-dir wp-login.php -U {c.getPath("reportDir")}/webSSL/wp-users.txt -P {c.getPath("reportDir")}/webSSL/john-cool-list.txt threads 50 | tee {c.getPath("reportDir")}/webSSL/wordpress-john-cewl-brute.txt
        else
            echo "John wordlist is empty :("
        fi
        sleep 1
        if grep -i "No Valid Passwords Found" {c.getPath("reportDir")}/webSSL/wordpress-john-cewl-brute.txt; then
            wpscan --no-update --disable-tls-checks --url https://{self.target}:{ssl_port}/ --wp-content-dir wp-login.php -U {c.getPath("reportDir")}/webSSL/wp-users.txt -P /usr/share/wordlists/fasttrack.txt threads 50 | tee {c.getPath("reportDir")}/webSSL/wordpress-fasttrack-brute.txt
        fi
    fi
fi
                                            """.rstrip()
                                            try:
                                                with open(
                                                    f"""{c.getPath("reportDir")}/webSSL/wordpressBrute.sh""",
                                                    "w",
                                                ) as wpb:
                                                    print(
                                                        "Creating wordpress Brute Force Script..."
                                                    )
                                                    wpb.write(manual_brute_force_script)
                                                call(
                                                    f"""chmod +x {c.getPath("reportDir")}/webSSL/wordpressBrute.sh""",
                                                    shell=True,
                                                )
                                            except FileNotFoundError as fnf_error:
                                                print(fnf_error)
                                                continue
                                            if "Drupal" in cms:
                                                drupal_cmd = f"""droopescan scan drupal -u https://{self.target}:{ssl_port}/ -t 32 | tee {c.getPath("reportDir")}/webSSL/drupalscan-{self.target}-{ssl_port}.log"""
                                                cms_commands.append(drupal_cmd)
                                            if "Joomla" in cms:
                                                joomla_cmd = f"""joomscan --url https://{self.target}:{ssl_port}/ -ec | tee {c.getPath("reportDir")}/webSSL/joomlascan-{self.target}-{ssl_port}.log"""
                                                cms_commands.append(joomla_cmd)
                                            if "Magento" in cms:
                                                magento_cmd = f"""cd /opt/magescan && bin/magescan scan:all -n --insecure https://{self.target}:{ssl_port}/ | tee {c.getPath("reportDir")}/webSSL/magentoscan-{self.target}-{ssl_port}.log && cd - &>/dev/null"""
                                                cms_commands.append(magento_cmd)
                                            if "WebDAV" in cms:
                                                webdav_cmd = f"""davtest -move -sendbd auto -url https://{self.target}:{ssl_port}/ | tee {c.getPath("reportDir")}/webSSL/davtestscan-{self.target}-{ssl_port}.log"""
                                                webdav_cmd2 = f"""nmap -Pn -v -sV -p {ssl_port} --script=http-iis-webdav-vuln.nse -oA {self.target}-Report/nmap/webdav {self.target}"""
                                                cms_commands.append(webdav_cmd)
                                                cms_commands.append(webdav_cmd2)
                                        else:
                                            for hn in hostnames:
                                                for whatweb_hn in whatweb_hostnames:
                                                    if hn in whatweb_hn:
                                                        if "WordPress" in cms:
                                                            wpscan_cmd = f"""wpscan --no-update --disable-tls-checks --url https://{hn}:{ssl_port}/ --wp-content-dir wp-content --enumerate vp,vt,cb,dbe,u,m --plugins-detection aggressive | tee {c.getPath("reportDir")}/webSSL/wpscan-{hn}-{ssl_port}.log"""
                                                            cms_commands.append(
                                                                wpscan_cmd
                                                            )
                                                        if "Drupal" in cms:
                                                            drupal_cmd = f"""droopescan scan drupal -u https://{hn}:{ssl_port}/ -t 32 | tee {c.getPath("reportDir")}/webSSL/drupalscan-{hn}-{ssl_port}.log"""
                                                            cms_commands.append(
                                                                drupal_cmd
                                                            )
                                                        if "Joomla" in cms:
                                                            joomla_cmd = f"""joomscan --url https://{hn}:{ssl_port}/ -ec | tee {c.getPath("reportDir")}/webSSL/joomlascan-{hn}-{ssl_port}.log"""
                                                            cms_commands.append(
                                                                joomla_cmd
                                                            )
                                                        if "Magento" in cms:
                                                            magento_cmd = f"""cd /opt/magescan && bin/magescan scan:all https://{hn}:{ssl_port}/ | tee {c.getPath("reportDir")}/webSSL/magentoscan-{hn}-{ssl_port}.log && cd - &>/dev/null"""
                                                            cms_commands.append(
                                                                magento_cmd
                                                            )
                                                        if "WebDAV" in cms:
                                                            webdav_cmd = f"""davtest -move -sendbd auto -url https://{hn}:{ssl_port}/ | tee {c.getPath("reportDir")}/webSSL/davtestscan-{hn}-{ssl_port}.log"""
                                                            webdav_cmd2 = f"""nmap -Pn -v -sV -p {ssl_port} --script=http-iis-webdav-vuln.nse -oA {c.getPath("reportDir")}/nmap/webdav {self.target}"""
                                                            cms_commands.append(
                                                                webdav_cmd
                                                            )
                                                            cms_commands.append(
                                                                webdav_cmd2
                                                            )

            sorted_commands = sorted(set(cms_commands))
            commands_to_run = []
            for i in sorted_commands:
                commands_to_run.append(i)
            mpCmds = tuple(commands_to_run)
            self.cms_processes = mpCmds
