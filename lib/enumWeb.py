#!/usr/bin/env python3

import os
from sty import fg, bg, ef, rs
from lib import nmapParser
from lib import domainFinder
from subprocess import call
import glob
from bs4 import BeautifulSoup  # SoupStrainer
import requests
from lib import dnsCrawl
from utils import config_paths


class EnumWeb:
    def __init__(self, target):
        self.target = target
        self.processes = ""
        self.cms_processes = ""
        self.proxy_processes = ""

    def Scan(self):
        green = fg.li_green
        reset = fg.rs
        cmd_info = "[" + green + "+" + reset + "]"
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        http_ports = np.http_ports
        if len(http_ports) == 0:
            pass
        else:
            print(f"""{fg.li_cyan} Enumerating HTTP Ports! {fg.rs}""")
            dn = domainFinder.DomainFinder(self.target)
            dn.getRedirect()
            hostnames = dn.redirect_hostname
            c = config_paths.Configurator(self.target)
            c.createConfig()
            c.cmdConfig()
            if not os.path.exists(f"""{c.getPath("webDir")}"""):
                os.makedirs(f"""{c.getPath("webDir")}""")
            if not os.path.exists(f"""{c.getPath("aquatoneDir")}"""):
                os.makedirs(f"""{c.getPath("aquatoneDir")}""")
            dc = dnsCrawl.checkSource(self.target)
            dc.getLinks()
            htb_source_domains = dc.htb_source_domains
            sc = dnsCrawl.sourceCommentChecker(self.target)
            sc.extract_source_comments()
            commands = ()
            another_array_of_hostnames = []
            if len(htb_source_domains) != 0:
                for d in htb_source_domains:
                    another_array_of_hostnames.append(d)
            if len(hostnames) != 0:
                for d in hostnames:
                    another_array_of_hostnames.append(d)
            if len(another_array_of_hostnames) != 0:
                sorted_hostnames = sorted(set(another_array_of_hostnames))
                for hostname in sorted_hostnames:
                    for port in http_ports:
                        if not os.path.exists(
                            f"""{c.getPath("eyewitnessDir")}-{hostname}-{port}"""
                        ):
                            os.makedirs(
                                f"""{c.getPath("eyewitnessDir")}-{hostname}-{port}"""
                            )
                        commands = commands + (
                            f"""echo {cmd_info} {green} '{c.getCmd("whatweb")}{hostname}:{port} | tee {c.getPath("webWhatweb")}-{hostname}-{port}.txt' {reset}""",
                            f"""{c.getCmd("whatweb")}{hostname}:{port} | tee {c.getPath("webWhatweb")}-{hostname}-{port}.txt""",
                            f"""echo {cmd_info} {green} '{c.getCmd("eyeWitness")} {c.getPath("eyewitnessDir")}-{hostname}-{port}' {reset}""",
                            f"""cd /opt/EyeWitness && echo 'http://{hostname}:{port}' > eyefile.txt && {c.getCmd("eyeWitness")} {c.getPath("eyewitnessDir")}-{hostname}-{port} && cd - &>/dev/null""",
                            f"""echo {cmd_info} {green} 'wafw00f http://{hostname}:{port} | tee {c.getPath("webWafw00f")}-{hostname}-{port}.txt' {reset}""",
                            f"""wafw00f http://{hostname}:{port} | tee {c.getPath("webWafw00f")}-{hostname}-{port}.txt""",
                            f"""echo {cmd_info} {green} 'curl -sSik http://{hostname}:{port}/robots.txt -m 10 -o {c.getPath("webRobots")}-{hostname}-{port}.txt &>/dev/null' {reset}""",
                            f"""curl -sSik http://{hostname}:{port}/robots.txt -m 10 -o {c.getPath("webRobots")}-{hostname}-{port}.txt &>/dev/null""",
                            f"""echo {cmd_info} {green} '{c.getCmd("dirsearch")}{hostname}:{port}/ -t 50 -e {c.getCmd("ext")} -w {c.getPath("wlDict")} -x {c.getCmd("hc")} --plain-text-report {c.getPath("webDs")}-{hostname}-{port}.log' {reset}""",
                            f"""{c.getCmd("dirsearch")}{hostname}:{port}/ -t 50 -e {c.getCmd("ext")} -w {c.getPath("wlDict")} -x {c.getCmd("hc")} --plain-text-report {c.getPath("webDs")}-{hostname}-{port}.log""",
                            f"""echo {cmd_info} {green} '{c.getCmd("dirsearch")}{hostname}:{port}/ -t 80 -e {c.getCmd("ext")} -w {c.getPath("Big")} -x {c.getCmd("hc")} --plain-text-report {c.getPath("webDsB")}-{hostname}-{port}.log' {reset}""",
                            f"""{c.getCmd("dirsearch")}{hostname}:{port}/ -t 80 -e {c.getCmd("ext")} -w {c.getPath("Big")} -x {c.getCmd("hc")} --plain-text-report {c.getPath("webDsB")}-{hostname}-{port}.log""",
                            f"""echo {cmd_info} {green} 'nikto -ask=no -host http://{hostname}:{port} >{c.getPath("webNikto")}-{hostname}-{port}.txt 2>&1 &' {reset}""",
                            f"""nikto -ask=no -host http://{hostname}:{port} >{c.getPath("webNikto")}-{hostname}-{port}.txt 2>&1 &""",
                        )
            else:
                for port in http_ports:
                    if not os.path.exists(
                        f"""{self.target}-Report/web/eyewitness-{self.target}-{port}"""
                    ):
                        os.makedirs(
                            f"""{self.target}-Report/web/eyewitness-{self.target}-{port}"""
                        )
                    commands = commands + (
                        f"""echo {cmd_info} {green} '{c.getCmd("whatweb")}{self.target}:{port} | tee {c.getPath("webWhatweb")}-{port}.txt' {reset}""",
                        f"""{c.getCmd("whatweb")}{self.target}:{port} | tee {c.getPath("webWhatweb")}-{port}.txt""",
                        f"""echo {cmd_info} {green} '{c.getCmd("eyeWitness")} {c.getPath("eyewitnessDirT")}-{port}' {reset}""",
                        f"""cd /opt/EyeWitness && echo 'http://{self.target}:{port}' >eyefile.txt && {c.getCmd("eyeWitness")} {c.getPath("eyewitnessDirT")}-{port} && cd - &>/dev/null""",
                        f"""echo {cmd_info} {green} 'wafw00f http://{self.target}:{port} | tee {c.getPath("webWafw00f")}-{port}.txt' {reset}""",
                        f"""wafw00f http://{self.target}:{port} | tee {c.getPath("webWafw00f")}-{port}.txt""",
                        f"""echo {cmd_info} {green} 'curl -sSik http://{self.target}:{port}/robots.txt -m 10 -o {c.getPath("webRobots")}-{port}.txt &>/dev/null' {reset}""",
                        f"""curl -sSik http://{self.target}:{port}/robots.txt -m 10 -o {c.getPath("webRobots")}-{port}.txt &>/dev/null""",
                        f"""echo {cmd_info} {green} '{c.getCmd("dirsearchT")}:{port}/ -t 50 -e {c.getCmd("ext")} -w {c.getPath("wlDict")} -x {c.getCmd("hc")} --plain-text-report {c.getPath("webDs")}-{port}.log' {reset}""",
                        f"""{c.getCmd("dirsearchT")}:{port}/ -t 50 -e {c.getCmd("ext")} -w {c.getPath("wlDict")} -x {c.getCmd("hc")} --plain-text-report {c.getPath("webDs")}-{port}.log""",
                        f"""echo {cmd_info} {green} '{c.getCmd("dirsearchT")}:{port}/ -t 80 -e {c.getCmd("ext")} -w {c.getPath("Big")} -x {c.getCmd("hc")} --plain-text-report {c.getPath("webDsB")}-{port}.log' {reset}""",
                        f"""{c.getCmd("dirsearchT")}:{port}/ -t 80 -e {c.getCmd("ext")} -w {c.getPath("Big")} -x {c.getCmd("hc")} --plain-text-report {c.getPath("webDsB")}-{port}.log""",
                        f"""echo {cmd_info} {green} 'nikto -ask=no -host http://{self.target}:{port} >{c.getPath("webNikto")}-{port}.txt 2>&1 &' {reset}""",
                        f"""nikto -ask=no -host http://{self.target}:{port} >{c.getPath("webNikto")}-{port}.txt 2>&1 &""",
                    )

            self.processes = commands

    def ScanWebOption(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        http_ports = np.http_ports
        dn = domainFinder.DomainFinder(self.target)
        dn.getRedirect()
        hostnames = dn.redirect_hostname
        if len(http_ports) == 0:
            pass
        else:
            green = fg.li_green
            reset = fg.rs
            cmd_info = "[" + green + "+" + reset + "]"
            print(
                f"""{fg.li_cyan}Enumerating HTTP Ports, Running the following commands: {reset}"""
            )
            c = config_paths.Configurator(self.target)
            c.createConfig()
            c.cmdConfig()
            if not os.path.exists(f"""{c.getPath("webDir")}"""):
                os.makedirs(f"""{c.getPath("webDir")}""")
            if not os.path.exists(f"""{c.getPath("aquatoneDir")}"""):
                os.makedirs(f"""{c.getPath("aquatoneDir")}""")
            if hostnames:
                sorted_hostnames = sorted(set(hostnames))
                commands = ()
                for hostname in sorted_hostnames:
                    for port in http_ports:
                        if not os.path.exists(
                            f"""{c.getPath("eyewitnessDir")}-{hostname}-{port}"""
                        ):
                            os.makedirs(
                                f"""{c.getPath("eyewitnessDir")}-{hostname}-{port}"""
                            )
                        commands = commands + (
                            f"""echo {cmd_info} {green} 'whatweb -v -a 3 http://{hostname}:{port} | tee {c.getPath("webWhatweb")}-{hostname}-{port}.txt' {reset}""",
                            f"""whatweb -v -a 3 http://{hostname}:{port} | tee {c.getPath("webWhatweb")}-{hostname}-{port}.txt""",
                            f"""echo {cmd_info} {green} '{c.getCmd("eyeWitness")} {c.getPath("eyewitnessDir")}-{hostname}-{port}' {reset}""",
                            f"""cd /opt/EyeWitness && echo 'http://{hostname}:{port}' > eyefile.txt && {c.getCmd("eyeWitness")} {c.getPath("eyewitnessDir")}-{hostname}-{port} && cd - &>/dev/null""",
                            f"""echo {cmd_info} {green} 'wafw00f http://{hostname}:{port} | tee {c.getPath("webWafw00f")}-{hostname}-{port}.txt' {reset}""",
                            f"""wafw00f http://{hostname}:{port} | tee {c.getPath("webWafw00f")}-{hostname}-{port}.txt""",
                            f"""echo {cmd_info} {green} 'curl -sSik http://{hostname}:{port}/robots.txt -m 10 -o {c.getPath("webRobots")}-{hostname}-{port}.txt &>/dev/null' {reset}""",
                            f"""curl -sSik http://{hostname}:{port}/robots.txt -m 10 -o {c.getPath("webRobots")}-{hostname}-{port}.txt &>/dev/null""",
                            f"""echo {cmd_info} {green} '{c.getCmd("dirsearch")}{hostname}:{port}/ -t 80 -e php,asp,aspx,html,txt -w {c.getCmd("dlistMed")} -x {c.getCmd("hc")} --plain-text-report {c.getPath("webDirsearchDLM")}-{hostname}-{port}.log' {reset}""",
                            f"""{c.getCmd("dirsearch")}{hostname}:{port}/ -t 80 -e php,asp,aspx,html,txt -w {c.getCmd("dlistMed")} -x {c.getCmd("hc")} --plain-text-report {c.getPath("webDirsearchDLM")}-{hostname}-{port}.log""",
                            f"""echo {cmd_info} {green} '{c.getCmd("dirsearch")}{hostname}:{port}/ -t 50 -e {c.getCmd("ext2")} -x {c.getCmd("hc")} -w {c.getPath("raftLarge")} --plain-text-report {c.getPath("webDirsearchRF")}-{hostname}-{port}.log' {reset}""",
                            f"""{c.getCmd("dirsearch")}{hostname}:{port}/ -t 50 -e {c.getCmd("ext2")} -x {c.getCmd("hc")} -w {c.getPath("raftLarge")} --plain-text-report {c.getPath("webDirsearchRF")}-{hostname}-{port}.log""",
                            f"""echo {cmd_info} {green} '{c.getCmd("dirsearch")}{hostname}:{port}/ -t 50 -e php,asp,aspx,html,txt -x {c.getCmd("hc")} -w {c.getPath("raftLd")} --plain-text-report {c.getPath("webDirsearchRLD")}-{hostname}-{port}.log' {reset}""",
                            f"""{c.getCmd("dirsearch")}{hostname}:{port}/ -t 50 -e php,asp,aspx,html,txt -x {c.getCmd("hc")} -w {c.getPath("raftLd")} --plain-text-report {c.getPath("webDirsearchRLD")}-{hostname}-{port}.log""",
                            f"""echo {cmd_info} {green} '{c.getCmd("dirsearch")}{hostname}:{port}/ -t 50 -e php,asp,aspx,txt,html -w wordlists/foreign.txt -x {c.getCmd("hc")} --plain-text-report {c.getPath("webDirsearchF")}-{hostname}-{port}.log' {reset}""",
                            f"""{c.getCmd("dirsearch")}{hostname}:{port}/ -t 50 -e php,asp,aspx,txt,html -w wordlists/foreign.txt -x {c.getCmd("hc")} --plain-text-report {c.getPath("webDirsearchF")}-{hostname}-{port}.log""",
                            f"""echo {cmd_info} {green} 'nikto -ask=no -host http://{hostname}:{port} >{c.getPath("webNikto")}-{hostname}-{port}.txt 2>&1 &' {reset}""",
                            f"""nikto -ask=no -host http://{hostname}:{port} >{c.getPath("webNikto")}-{hostname}-{port}.txt 2>&1 &""",
                        )
            else:
                commands = ()
                for port in http_ports:
                    if not os.path.exists(f"""{c.getPath("eyewitnessDirT")}-{port}"""):
                        os.makedirs(f"""{c.getPath("eyewitnessDirT")}-{port}""")
                    commands = commands + (
                        f"""echo {cmd_info} {green} 'whatweb -v -a 3 http://{self.target}:{port} | tee {c.getPath("webWhatweb")}-{port}.txt' {reset}""",
                        f"""whatweb -v -a 3 http://{self.target}:{port} | tee {c.getPath("webWhatweb")}-{port}.txt""",
                        f"""echo {cmd_info} {green} '{c.getCmd("eyeWitness")} {c.getPath("eyewitnessDirT")}-{port}' {reset}""",
                        f"""cd /opt/EyeWitness && echo 'http://{self.target}:{port}' >eyefile.txt && {c.getCmd("eyeWitness")} {c.getPath("eyewitnessDirT")}-{port} && cd - &>/dev/null""",
                        f"""echo {cmd_info} {green} 'wafw00f http://{self.target}:{port} | tee {c.getPath("webWafw00f")}-{port}.txt' {reset}""",
                        f"""wafw00f http://{self.target}:{port} | tee {c.getPath("webWafw00f")}-{port}.txt""",
                        f"""echo {cmd_info} {green} 'curl -sSik http://{self.target}:{port}/robots.txt -m 10 -o {c.getPath("webRobots")}-{port}.txt &>/dev/null' {reset}""",
                        f"""curl -sSik http://{self.target}:{port}/robots.txt -m 10 -o {c.getPath("webRobots")}-{port}.txt &>/dev/null""",
                        f"""echo {cmd_info} {green} '{c.getCmd("dirsearchT")}:{port}/ -t 80 -e php,asp,aspx,html,txt -w {c.getCmd("dlistMed")} -x {c.getCmd("hc")} --plain-text-report {c.getPath("webDirsearchDLM")}-{port}.log' {reset}""",
                        f"""{c.getCmd("dirsearchT")}:{port}/ -t 80 -e php,asp,aspx,html,txt -w {c.getCmd("dlistMed")} -x {c.getCmd("hc")} --plain-text-report {c.getPath("webDirsearchDLM")}-{port}.log""",
                        f"""echo {cmd_info} {green} '{c.getCmd("dirsearchT")}:{port}/ -t 50 -e {c.getCmd("ext2")} -x {c.getCmd("hc")} -w {c.getPath("raftLarge")} --plain-text-report {c.getPath("webDirsearchRF")}-{port}.log' {reset}""",
                        f"""{c.getCmd("dirsearchT")}:{port}/ -t 50 -e {c.getCmd("ext2")} -x {c.getCmd("hc")} -w {c.getPath("raftLarge")} --plain-text-report {c.getPath("webDirsearchRF")}-{port}.log""",
                        f"""echo {cmd_info} {green} '{c.getCmd("dirsearchT")}:{port}/ -t 50 -e php,asp,aspx,html,txt -x {c.getCmd("hc")} -w {c.getPath("raftLd")} --plain-text-report {c.getPath("webDirsearchRLD")}-{port}.log' {reset}""",
                        f"""{c.getCmd("dirsearchT")}:{port}/ -t 50 -e php,asp,aspx,html,txt -x {c.getCmd("hc")} -w {c.getPath("raftLd")} --plain-text-report {c.getPath("webDirsearchRLD")}-{port}.log""",
                        f"""echo {cmd_info} {green} '{c.getCmd("dirsearchT")}:{port}/ -t 50 -e php,asp,aspx,html,txt -x {c.getCmd("hc")} -w {cwd}/wordlists/foreign.txt --plain-text-report {c.getPath("webDirsearchF")}-{port}.log' {reset}""",
                        f"""{c.getCmd("dirsearchT")}:{port}/ -t 50 -e php,asp,aspx,html,txt -x {c.getCmd("hc")} -w {cwd}/wordlists/foreign.txt --plain-text-report {c.getPath("webDirsearchF")}-{port}.log""",
                        f"""echo {cmd_info} {green} 'nikto -ask=no -host http://{self.target}:{port} >{c.getPath("webNikto")}-{port}.txt 2>&1 &' {reset}""",
                        f"""nikto -ask=no -host http://{self.target}:{port} >{c.getPath("webNikto")}-{port}.txt 2>&1 &""",
                    )

            self.processes = commands

    def CMS(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        http_ports = np.http_ports
        cms_commands = []
        if len(http_ports) == 0:
            pass
        else:
            c = config_paths.Configurator(self.target)
            c.createConfig()
            c.cmdConfig()
            for http_port in http_ports:
                whatweb_files = []
                dir_list = [
                    d
                    for d in glob.iglob(
                        f"""{c.getPath("reportGlob")}""", recursive=True
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
                                if str(http_port) in rf:
                                    whatweb_files.append(rf)
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
                                        if "WordPress" in cms:
                                            wpscan_cmd = f"""wpscan --no-update --url http://{self.target}:{http_port}/ --wp-content-dir wp-content --enumerate vp,vt,cb,dbe,u,m --plugins-detection aggressive | tee {c.getPath("webWPScan")}-{http_port}.log"""
                                            cms_commands.append(wpscan_cmd)
                                            manual_brute_force_script = f"""
#!/bin/bash

if [[ -n $(grep -i "User(s) Identified" {c.getPath("reportDir")}/web/wpscan-{http_port}.log) ]]; then
    grep -w -A 100 "User(s)" {c.getPath("reportDir")}/web/wpscan-{http_port}.log | grep -w "[+]" | cut -d " " -f 2 | head -n -7 >{c.getPath("reportDir")}/web/wp-users.txt
    cewl http://{self.target}:{http_port}/ -m 3 -w {c.getPath("reportDir")}/web/cewl-list.txt
    sleep 10
    echo "Adding John Rules to Cewl Wordlist!"
    john --rules --wordlist={c.getPath("reportDir")}/web/cewl-list.txt --stdout >{c.getPath("reportDir")}/web/john-cool-list.txt
    sleep 3
    # brute force again with wpscan
    wpscan --no-update --url http://{self.target}:{http_port}/ --wp-content-dir wp-login.php -U {c.getPath("reportDir")}/web/wp-users.txt -P {c.getPath("reportDir")}/web/cewl-list.txt threads 50 | tee {c.getPath("reportDir")}/web/wordpress-cewl-brute.txt
    sleep 1
    if grep -i "No Valid Passwords Found" wordpress-cewl-brute2.txt; then
        if [ -s {c.getPath("reportDir")}/web/john-cool-list.txt ]; then
            wpscan --no-update --url http://{self.target}:{http_port}/ --wp-content-dir wp-login.php -U {c.getPath("reportDir")}/web/wp-users.txt -P {c.getPath("reportDir")}/web/john-cool-list.txt threads 50 | tee {c.getPath("reportDir")}/web/wordpress-john-cewl-brute.txt
        else
            echo "John wordlist is empty :("
        fi
        sleep 1
        if grep -i "No Valid Passwords Found" {c.getPath("reportDir")}/web/wordpress-john-cewl-brute.txt; then
            wpscan --no-update --url http://{self.target}:{http_port}/ --wp-content-dir wp-login.php -U {c.getPath("reportDir")}/web/wp-users.txt -P /usr/share/wordlists/fasttrack.txt threads 50 | tee {c.getPath("reportDir")}/web/wordpress-fasttrack-brute.txt
        fi
    fi
fi
                                            """.rstrip()
                                            try:
                                                with open(
                                                    f"""{c.getPath("webWPBrute")}""",
                                                    "w",
                                                ) as wpb:
                                                    print(
                                                        "Creating wordpress Brute Force Script..."
                                                    )
                                                    wpb.write(manual_brute_force_script)
                                                call(
                                                    f"""chmod +x {c.getPath("webWPBrute")}""",
                                                    shell=True,
                                                )
                                            except FileNotFoundError as fnf_error:
                                                print(fnf_error)

                                        if "Drupal" in cms:
                                            drupal_cmd = f"""droopescan scan drupal -u http://{self.target}:{http_port}/ -t 32 | tee {c.getPath("reportDir")}/web/drupalscan-{self.target}-{http_port}.log"""
                                            cms_commands.append(drupal_cmd)
                                        if "Joomla" in cms:
                                            joomla_cmd = f"""joomscan --url http://{self.target}:{http_port}/ -ec | tee {c.getPath("reportDir")}/web/joomlascan-{self.target}-{http_port}.log"""
                                            cms_commands.append(joomla_cmd)
                                        if "Magento" in cms:
                                            magento_cmd = f"""cd /opt/magescan && bin/magescan scan:all http://{self.target}:{http_port}/ | tee {c.getPath("reportDir")}/web/magentoscan-{self.target}-{http_port}.log && cd - &>/dev/null"""
                                            cms_commands.append(magento_cmd)
                                        if "WebDAV" in cms:
                                            webdav_cmd = f"""davtest -move -sendbd auto -url http://{self.target}:{http_port}/ | tee {c.getPath("reportDir")}/web/davtestscan-{self.target}-{http_port}.log"""
                                            webdav_cmd2 = f"""nmap -Pn -v -sV -p {http_port} --script=http-iis-webdav-vuln.nse -oA {self.target}-Report/nmap/webdav {self.target}"""
                                            cms_commands.append(webdav_cmd)
                                            cms_commands.append(webdav_cmd2)
                                        if "tomcat" in cms:
                                            tomcat_cmd = f"""hydra -C /usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt -s {http_port} {self.target} http-get /manager/html"""
                                            print("Manual Brute Force Command to run")
                                            print(tomcat_cmd)

            sorted_commands = sorted(set(cms_commands))
            commands_to_run = []
            for i in sorted_commands:
                commands_to_run.append(i)
            mpCmds = tuple(commands_to_run)
            self.cms_processes = mpCmds

    def proxyScan(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        npp = nmapParser.NmapParserFunk(self.target)
        npp.openProxyPorts()
        proxy_http_ports = npp.proxy_http_ports
        proxy_ports = np.proxy_ports
        if len(proxy_http_ports) == 0:
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
            if not os.path.exists(f"""{c.getPath("proxyWeb")}"""):
                os.makedirs(f"""{c.getPath("proxyWeb")}""")
            proxy_commands = ()
            for proxy in proxy_ports:
                print(
                    f"""{fg.li_cyan} Enumerating HTTP Ports Through Port: {proxy}, Running the following commands: {fg.rs}"""
                )
                if not os.path.exists(f"""{c.getPath("eyewitnessDirPT")}-{proxy}"""):
                    os.makedirs(f"""{c.getPath("eyewitnessDirPT")}-{proxy}""")
                proxy_commands = proxy_commands + (
                    f"""cd /opt/EyeWitness && echo 'http://{self.target}:{proxy}' > eyefile.txt && {c.getCmd("eyeWitness")} {c.getPath("eyewitnessDirPT")}-{proxy} && cd - &>/dev/null""",
                    f"""whatweb -v -a 3 http://{self.target}:{proxy} | tee {c.getPath("webWhatwebPT")}-{proxy}.txt""",
                )
                if len(proxy_http_ports) != 0:
                    for proxy_http_port in proxy_http_ports:
                        proxy_commands = proxy_commands + (
                            f"""echo {cmd_info} {green} 'whatweb -v -a 3 --proxy {self.target}:{proxy} http://127.0.0.1:{proxy_http_port} | tee {c.getPath("webWhatwebProxy")}-{proxy_http_port}.txt' {reset}""",
                            f"""whatweb -v -a 3 --proxy {self.target}:{proxy} http://127.0.0.1:{proxy_http_port} | tee {c.getPath("webWhatwebProxy")}-{proxy_http_port}.txt""",
                            f"""echo {cmd_info} {green} '{c.getCmd("dirsearchProxy")} {c.getCmd("hc")} -t 50 -w {c.getPath("wlDict")} --proxy {self.target}:{proxy} -u http://127.0.0.1:{proxy_http_port} --plain-text-report {c.getPath("webDsP")}-{proxy}-{proxy_http_port}.log' {reset}""",
                            f"""{c.getCmd("dirsearchProxy")} {c.getCmd("hc")} -t 50 -w {c.getPath("wlDict")} --proxy {self.target}:{proxy} -u http://127.0.0.1:{proxy_http_port} --plain-text-report {c.getPath("webDsP")}-{proxy}-{proxy_http_port}.log""",
                            f"""echo {cmd_info} {green} '{c.getCmd("dirsearchProxy")} {c.getCmd("hc")} -t 50 -w {c.getPath("Big")} --proxy {self.target}:{proxy} -u http://127.0.0.1:{proxy_http_port} --plain-text-report {c.getPath("webDsPB")}-{proxy}-{proxy_http_port}.log' {reset}""",
                            f"""{c.getCmd("dirsearchProxy")} {c.getCmd("hc")} -t 50 -w {c.getPath("Big")} --proxy {self.target}:{proxy} -u http://127.0.0.1:{proxy_http_port} --plain-text-report {c.getPath("webDsPB")}-{proxy}-{proxy_http_port}.log""",
                            f"""echo {cmd_info} {green} 'nikto -ask=no -host http://127.0.0.1:{proxy_http_port}/ -useproxy http://{self.target}:{proxy}/ > {c.getPath("webNiktoP")}-{proxy_http_port}-proxy-scan.txt 2>&1 &' {reset}""",
                            f"""nikto -ask=no -host http://127.0.0.1:{proxy_http_port}/ -useproxy http://{self.target}:{proxy}/ > {c.getPath("webNiktoP")}-{proxy_http_port}-proxy-scan.txt 2>&1 &""",
                        )
            self.proxy_processes = proxy_commands

    def getLinks(self):
        url = f"""http://{self.target}"""
        c = config_paths.Configurator(self.target)
        c.createConfig()
        page = requests.get(url)
        data = page.text
        soup = BeautifulSoup(data)
        links = []
        for link in soup.find_all("a"):
            links.append(link.get("href"))
        if len(links) != 0:
            try:
                with open(f"""{c.getPath("weblinks")}""", "w") as l:
                    for link in links:
                        l.write(link)
            except FileNotFoundError as fnf_error:
                print(fnf_error)
