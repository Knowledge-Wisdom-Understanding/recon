#!/usr/bin/env python3

import os
import time
from sty import fg, bg, ef, rs, RgbFg
from lib import nmapParser
from lib import domainFinder
from subprocess import call, check_output
import glob
from bs4 import BeautifulSoup, SoupStrainer
import requests


class EnumWeb:
    def __init__(self, target):
        self.target = target
        self.processes = ""
        self.cms_processes = ""
        self.proxy_processes = ""
        self.redirect_hostname = []

    def Scan(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        http_ports = np.http_ports
        dn = domainFinder.DomainFinder(self.target)
        dn.getRedirect()
        hostnames = dn.redirect_hostname
        # print(hostnames)
        cwd = os.getcwd()
        reportDir = f"{cwd}/{self.target}-Report"
        if len(http_ports) == 0:
            pass
        else:
            a = f"{fg.li_cyan} Enumerating HTTP Ports, Running the following commands: {fg.rs}"

            print(a)
            if not os.path.exists(f"{self.target}-Report/web"):
                os.makedirs(f"{self.target}-Report/web")
            if not os.path.exists(f"{self.target}-Report/aquatone"):
                os.makedirs(f"{self.target}-Report/aquatone")
            http_string_ports = ",".join(map(str, http_ports))
            if hostnames:
                sorted_hostnames = sorted(set(hostnames))
                for hostname in sorted_hostnames:
                    # print("loop", hostname)
                    for port in http_ports:
                        if not os.path.exists(
                            f"{self.target}-Report/web/eyewitness-{hostname}-{port}"
                        ):
                            os.makedirs(f"{self.target}-Report/web/eyewitness-{hostname}-{port}")
                        commands = (
                            f"whatweb -v -a 3 http://{hostname}:{port} | tee {reportDir}/web/whatweb-{hostname}-{port}.txt",
                            f"cd /opt/EyeWitness && echo 'http://{hostname}:{port}' > eyefile.txt && ./EyeWitness.py --threads 5 --ocr --no-prompt --active-scan --all-protocols --web -f eyefile.txt -d {reportDir}/web/eyewitness-{hostname}-{port} && cd - &>/dev/null",
                            f"wafw00f http://{hostname}:{port} | tee {reportDir}/web/wafw00f-{hostname}-{port}.txt",
                            f"curl -sSik http://{hostname}:{port}/robots.txt -m 10 -o {reportDir}/web/robots-{hostname}-{port}.txt &>/dev/null",
                            f"python3 /opt/dirsearch/dirsearch.py -u http://{hostname}:{port} -t 50 -e php,asp,aspx,txt,html -w wordlists/dicc.txt -x 403,500 --plain-text-report {reportDir}/web/dirsearch-{hostname}-{port}.log",
                            f"python3 /opt/dirsearch/dirsearch.py -u http://{hostname}:{port} -t 80 -e php -w /usr/share/wordlists/dirb/big.txt -f -x 403,500 --plain-text-report {reportDir}/web/dirsearch-big-{hostname}-{port}.log",
                            f"nikto -ask=no -host http://{hostname}:{port} >{reportDir}/web/niktoscan-{hostname}-{port}.txt 2>&1 &",
                        )
                        self.processes = commands
                        # print(self.processes)
            else:
                for port in http_ports:
                    if not os.path.exists(
                        f"{self.target}-Report/web/eyewitness-{self.target}-{port}"
                    ):
                        os.makedirs(f"{self.target}-Report/web/eyewitness-{self.target}-{port}")
                    commands = (
                        f"whatweb -v -a 3 http://{self.target}:{port} | tee {reportDir}/web/whatweb-{port}.txt",
                        f"cd /opt/EyeWitness && echo 'http://{self.target}:{port}' >eyefile.txt && ./EyeWitness.py --threads 5 --ocr --no-prompt --active-scan --all-protocols --web -f eyefile.txt -d {reportDir}/web/eyewitness-{self.target}-{port} && cd - &>/dev/null",
                        f"wafw00f http://{self.target}:{port} | tee {reportDir}/web/wafw00f-{port}.txt",
                        f"curl -sSik http://{self.target}:{port}/robots.txt -m 10 -o {reportDir}/web/robots-{port}.txt &>/dev/null",
                        f"python3 /opt/dirsearch/dirsearch.py -u http://{self.target}:{port} -t 50 -e php,asp,aspx,txt,html -w wordlists/dicc.txt -x 403,500 --plain-text-report {reportDir}/web/dirsearch-{port}.log",
                        f"python3 /opt/dirsearch/dirsearch.py -u http://{self.target}:{port} -t 80 -e php -w /usr/share/wordlists/dirb/big.txt -f -x 403,500 --plain-text-report {reportDir}/web/dirsearch-big-{port}.log",
                        f"nikto -ask=no -host http://{self.target}:{port} >{reportDir}/web/niktoscan-{port}.txt 2>&1 &",
                    )

                self.processes = commands

    def ScanWebOption(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        http_ports = np.http_ports
        dn = domainFinder.DomainFinder(self.target)
        dn.getRedirect()
        hostnames = dn.redirect_hostname
        # print(hostnames)
        cwd = os.getcwd()
        reportDir = f"{cwd}/{self.target}-Report"
        if len(http_ports) == 0:
            pass
        else:
            a = f"{fg.li_cyan} Enumerating HTTP Ports, Running the following commands: {fg.rs}"

            print(a)
            if not os.path.exists(f"{self.target}-Report/web"):
                os.makedirs(f"{self.target}-Report/web")
            if not os.path.exists(f"{self.target}-Report/aquatone"):
                os.makedirs(f"{self.target}-Report/aquatone")
            http_string_ports = ",".join(map(str, http_ports))
            if hostnames:
                sorted_hostnames = sorted(set(hostnames))
                for hostname in sorted_hostnames:
                    # print("loop", hostname)
                    for port in http_ports:
                        if not os.path.exists(
                            f"{self.target}-Report/web/eyewitness-{hostname}-{port}"
                        ):
                            os.makedirs(f"{self.target}-Report/web/eyewitness-{hostname}-{port}")
                        commands = (
                            f"whatweb -v -a 3 http://{hostname}:{port} | tee {reportDir}/web/whatweb-{hostname}-{port}.txt",
                            f"cd /opt/EyeWitness && echo 'http://{hostname}:{port}' > eyefile.txt && ./EyeWitness.py --threads 5 --ocr --no-prompt --active-scan --all-protocols --web -f eyefile.txt -d {reportDir}/web/eyewitness-{hostname}-{port} && cd - &>/dev/null",
                            f"wafw00f http://{hostname}:{port} | tee {reportDir}/web/wafw00f-{hostname}-{port}.txt",
                            f"curl -sSik http://{hostname}:{port}/robots.txt -m 10 -o {reportDir}/web/robots-{hostname}-{port}.txt &>/dev/null",
                            f"python3 /opt/dirsearch/dirsearch.py -u http://{hostname}:{port} -t 80 -e php -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x 403,500 --plain-text-report {reportDir}/web/dirsearch-dlistmedium-{hostname}-{port}.log",
                            f"python3 /opt/dirsearch/dirsearch.py -u http://{hostname}:{port} -t 50 -e php,asp,aspx,html,txt,git,bak,tar,gz,7z,json,zip,rar,bz2,pdf,md,pl,cgi -x 403,500 -w /usr/share/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt --plain-text-report {reportDir}/web/dirsearch-{hostname}-{port}.log",
                            f"python3 /opt/dirsearch/dirsearch.py -u http://{hostname}:{port} -t 50 -e php,asp,aspx,html,txt -x 403,500 -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt --plain-text-report {reportDir}/web/dirsearch-{hostname}-{port}.log",
                            f"python3 /opt/dirsearch/dirsearch.py -u http://{hostname}:{port} -t 50 -e php,asp,aspx,txt,html -w wordlists/foreign.txt -x 403,500 --plain-text-report {reportDir}/web/dirsearch-{hostname}-{port}.log",
                            f"nikto -ask=no -host http://{hostname}:{port} >{reportDir}/web/niktoscan-{hostname}-{port}.txt 2>&1 &",
                        )
                        self.processes = commands
                        # print(self.processes)
            else:
                for port in http_ports:
                    if not os.path.exists(
                        f"{self.target}-Report/web/eyewitness-{self.target}-{port}"
                    ):
                        os.makedirs(f"{self.target}-Report/web/eyewitness-{self.target}-{port}")
                    commands = (
                        f"whatweb -v -a 3 http://{self.target}:{port} | tee {reportDir}/web/whatweb-{port}.txt",
                        f"cd /opt/EyeWitness && echo 'http://{self.target}:{port}' >eyefile.txt && ./EyeWitness.py --threads 5 --ocr --no-prompt --active-scan --all-protocols --web -f eyefile.txt -d {reportDir}/web/eyewitness-{self.target}-{port} && cd - &>/dev/null",
                        f"wafw00f http://{self.target}:{port} | tee {reportDir}/web/wafw00f-{port}.txt",
                        f"curl -sSik http://{self.target}:{port}/robots.txt -m 10 -o {reportDir}/web/robots-{port}.txt &>/dev/null",
                        f"python3 /opt/dirsearch/dirsearch.py -u http://{self.target}:{port} -t 80 -e php,asp,aspx,html,txt -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x 403,500 --plain-text-report {reportDir}/web/dirsearch-dlistmedium-{port}.log",
                        f"python3 /opt/dirsearch/dirsearch.py -u http://{self.target}:{port} -t 50 -e php,asp,aspx,html,txt,git,bak,tar,gz,7z,json,zip,rar,bz2,pdf,md,pl,cgi -x 403,500 -w /usr/share/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt --plain-text-report {reportDir}/web/dirsearch-raftfiles-{port}.log",
                        f"python3 /opt/dirsearch/dirsearch.py -u http://{self.target}:{port} -t 50 -e php,asp,aspx,html,txt -x 403,500 -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt --plain-text-report {reportDir}/web/dirsearch-raftdirs-{port}.log",
                        f"python3 /opt/dirsearch/dirsearch.py -u http://{self.target}:{port} -t 50 -e php,asp,aspx,html,txt -x 403,500 -w {cwd}/wordlists/foreign.txt --plain-text-report {reportDir}/web/dirsearch-{port}.log",
                        f"nikto -ask=no -host http://{self.target}:{port} >{reportDir}/web/niktoscan-{port}.txt 2>&1 &",
                    )

                self.processes = commands

    def CMS(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        http_ports = np.http_ports
        if len(http_ports) == 0:
            pass
        else:
            for http_port in http_ports:
                cwd = os.getcwd()
                reportPath = f"{cwd}/{self.target}-Report/*"
                reportDir = f"{cwd}/{self.target}-Report"
                whatweb_files = []
                cms_commands = []
                dir_list = [
                    d for d in glob.iglob(f"{reportPath}", recursive=True) if os.path.isdir(d)
                ]
                for d in dir_list:
                    reportFile_list = [
                        fname
                        for fname in glob.iglob(f"{d}/*", recursive=True)
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
                                fword = word.replace("[", " ").replace("]", " ").replace(",", " ")
                                for cms in cms_strings:
                                    if cms in fword:
                                        if "WordPress" in cms:
                                            wpscan_cmd = f"wpscan --no-update --url http://{self.target}:{http_port}/ --wp-content-dir wp-content --enumerate vp,vt,cb,dbe,u,m --plugins-detection aggressive | tee {reportDir}/web/wpscan-{http_port}.log"
                                            cms_commands.append(wpscan_cmd)
                                            manual_brute_force_script = f"""
#!/bin/bash

if [[ -n $(grep -i "User(s) Identified" {reportDir}/web/wpscan-{http_port}.log) ]]; then
    grep -w -A 100 "User(s)" {reportDir}/web/wpscan-{http_port}.log | grep -w "[+]" | cut -d " " -f 2 | head -n -7 >{reportDir}/web/wp-users.txt
    cewl http://{self.target}:{http_port}/ -m 3 -w {reportDir}/web/cewl-list.txt
    sleep 10
    echo "Adding John Rules to Cewl Wordlist!"
    john --rules --wordlist={reportDir}/web/cewl-list.txt --stdout >{reportDir}/web/john-cool-list.txt
    sleep 3
    # brute force again with wpscan
    wpscan --no-update --url http://{self.target}:{http_port}/ --wp-content-dir wp-login.php -U {reportDir}/web/wp-users.txt -P {reportDir}/web/cewl-list.txt threads 50 | tee {reportDir}/web/wordpress-cewl-brute.txt
    sleep 1
    if grep -i "No Valid Passwords Found" wordpress-cewl-brute2.txt; then
        if [ -s {reportDir}/web/john-cool-list.txt ]; then
            wpscan --no-update --url http://{self.target}:{http_port}/ --wp-content-dir wp-login.php -U {reportDir}/web/wp-users.txt -P {reportDir}/web/john-cool-list.txt threads 50 | tee {reportDir}/web/wordpress-john-cewl-brute.txt
        else
            echo "John wordlist is empty :("
        fi
        sleep 1
        if grep -i "No Valid Passwords Found" {reportDir}/web/wordpress-john-cewl-brute.txt; then
            wpscan --no-update --url http://{self.target}:{http_port}/ --wp-content-dir wp-login.php -U {reportDir}/web/wp-users.txt -P /usr/share/wordlists/fasttrack.txt threads 50 | tee {reportDir}/web/wordpress-fasttrack-brute.txt
        fi
    fi
fi
                                            """.rstrip()
                                            try:
                                                with open(
                                                    f"{reportDir}/web/wordpressBrute.sh", "w"
                                                ) as wpb:
                                                    print(
                                                        "Creating wordpress Brute Force Script..."
                                                    )
                                                    wpb.write(manual_brute_force_script)
                                                call(
                                                    f"chmod +x {reportDir}/web/wordpressBrute.sh",
                                                    shell=True,
                                                )
                                            except:
                                                continue

                                        if "Drupal" in cms:
                                            drupal_cmd = f"droopescan scan drupal -u http://{self.target}:{http_port}/ -t 32 | tee {reportDir}/web/drupalscan-{self.target}-{http_port}.log"
                                            cms_commands.append(drupal_cmd)
                                        if "Joomla" in cms:
                                            joomla_cmd = f"joomscan --url http://{self.target}:{http_port}/ -ec | tee {reportDir}/web/joomlascan-{self.target}-{http_port}.log"
                                            cms_commands.append(joomla_cmd)
                                        if "Magento" in cms:
                                            magento_cmd = f"cd /opt/magescan && bin/magescan scan:all http://{self.target}:{http_port}/ | tee {reportDir}/web/magentoscan-{self.target}-{http_port}.log && cd - &>/dev/null"
                                            cms_commands.append(magento_cmd)
                                        if "WebDAV" in cms:
                                            webdav_cmd = f"davtest -move -sendbd auto -url http://{self.target}:{http_port}/ | tee {reportDir}/web/davtestscan-{self.target}-{http_port}.log"
                                            webdav_cmd2 = f"nmap -Pn -v -sV -p {http_port} --script=http-iis-webdav-vuln.nse -oA {self.target}-Report/nmap/webdav {self.target}"
                                            cms_commands.append(webdav_cmd)
                                            cms_commands.append(webdav_cmd2)
                                        if "tomcat" in cms:
                                            tomcat_cmd = f"hydra -C /usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt -s {http_port} {self.target} http-get /manager/html"

                sorted_commands = sorted(set(cms_commands))
                commands_to_run = []
                for i in sorted_commands:
                    commands_to_run.append(i)
                mpCmds = tuple(commands_to_run)
                self.cms_processes = mpCmds

    def proxyScan(self):
        npp = nmapParser.NmapParserFunk(self.target)
        npp.openProxyPorts()
        proxy_http_ports = npp.proxy_http_ports
        proxy_ports = npp.proxy_ports
        web_proxy_cmds = []
        cwd = os.getcwd()
        reportDir = f"{cwd}/{self.target}-Report"
        cwd = os.getcwd()
        if len(proxy_http_ports) == 0:
            pass
        else:
            if not os.path.exists(f"{self.target}-Report/proxy"):
                os.makedirs(f"{self.target}-Report/proxy")
            if not os.path.exists(f"{self.target}-Report/proxy/web"):
                os.makedirs(f"{self.target}-Report/proxy/web")
            for proxy in proxy_ports:
                a = f"{fg.li_cyan} Enumerating HTTP Ports Through Port: {proxy}, Running the following commands: {fg.rs}"
                print(a)
                for proxy_http_port in proxy_http_ports:
                    proxy_http_string_ports = ",".join(map(str, proxy_http_ports))
                    proxy_whatwebCMD = f"whatweb -v -a 3 --proxy {self.target}:{proxy} http://127.0.0.1:{proxy_http_port} | tee {reportDir}/proxy/web/whatweb-proxy-{proxy_http_port}.txt"
                    web_proxy_cmds.append(proxy_whatwebCMD)
                    proxy_dirsearch_cmd = f"python3 /opt/dirsearch/dirsearch.py -e php,asp,aspx,txt,html -x 403,500 -t 50 -w wordlists/dicc.txt --proxy {self.target}:{proxy} -u http://127.0.0.1:{proxy_http_port} --plain-text-report {reportDir}/proxy/web/dirsearch-127.0.0.1-proxy-{proxy}-{proxy_http_port}.log"
                    web_proxy_cmds.append(proxy_dirsearch_cmd)
                    proxy_dirsearch_cmd2 = f"python3 /opt/dirsearch/dirsearch.py -u http://{self.target}:{proxy_http_port} -t 80 -e php,asp,aspx -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x 403,500 --plain-text-report {reportDir}/proxy/web/dirsearch-dlistsmall-127.0.0.1-proxy-{proxy_http_port}.log"
                    web_proxy_cmds.append(proxy_dirsearch_cmd2)
                    proxy_nikto_cmd = f"nikto -ask=no -host http://127.0.0.1:{proxy_http_port}/ -useproxy http://{self.target}:{proxy}/ > {reportDir}/proxy/web/nikto-port-{proxy_http_port}-proxy-scan.txt 2>&1 &"
                    web_proxy_cmds.append(proxy_nikto_cmd)

                    sorted_commands = sorted(set(web_proxy_cmds), reverse=True)
                    commands_to_run = []
                    for i in sorted_commands:
                        commands_to_run.append(i)
                    wpCmds = tuple(commands_to_run)
                    self.proxy_processes = wpCmds

    def getLinks(self):
        url = f"http://{self.target}"
        cwd = os.getcwd()
        reportDir = f"{cwd}/{self.target}-Report"
        page = requests.get(url)
        data = page.text
        soup = BeautifulSoup(data)
        links = []
        for link in soup.find_all("a"):
            links.append(link.get("href"))
        if len(links) != 0:
            try:
                with open(f"{reportDir}/web/links.txt", "w") as l:
                    for link in links:
                        l.write(link)
            except:
                pass
