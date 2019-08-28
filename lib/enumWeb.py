#!/usr/bin/env python3

import os
import time
from sty import fg, bg, ef, rs, RgbFg
from lib import nmapParser
import subprocess as s
import glob


class EnumWeb:
    def __init__(self, target):
        self.target = target
        self.processes = ""
        self.cms_processes = ""

    def Scan(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        http_ports = np.http_ports
        cwd = os.getcwd()
        if len(http_ports) == 0:
            pass
        else:
            a = f"{fg.cyan} Enumerating HTTP Ports, Running the following commands: {fg.rs}"

            print(a)
            if not os.path.exists(f"{self.target}-Report/web"):
                os.makedirs(f"{self.target}-Report/web")
            if not os.path.exists(f"{self.target}-Report/aquatone"):
                os.makedirs(f"{self.target}-Report/aquatone")
            http_string_ports = ",".join(map(str, http_ports))
            for port in http_ports:
                if not os.path.exists(
                    f"{self.target}-Report/web/eyewitness-{self.target}-{port}"
                ):
                    os.makedirs(
                        f"{self.target}-Report/web/eyewitness-{self.target}-{port}"
                    )
                commands = (
                    f"whatweb -v -a 3 http://{self.target}:{port} | tee {self.target}-Report/web/whatweb-{self.target}-{port}.txt",
                    f"cd /opt/EyeWitness && echo http://{self.target}:{port} >eyefile.txt && ./EyeWitness.py --threads 5 --ocr --no-prompt --active-scan --all-protocols --web -f eyefile.txt -d {cwd}/{self.target}-Report/web/eyewitness-{self.target}-{port} && cd - &>/dev/null",
                    f"wafw00f http://{self.target}:{port} | tee {self.target}-Report/web/wafw00f-{self.target}-{port}.txt",
                    f"curl -sSik http://{self.target}:{port}/robots.txt -m 10 -o {self.target}-Report/web/robots-{self.target}-{port}.txt &>/dev/null",
                    f"python3 /opt/dirsearch/dirsearch.py -u http://{self.target}:{port} -t 80 -e php,asp,aspx,txt,html -x 403,500 --plain-text-report {self.target}-Report/web/dirsearch-{self.target}-{port}.log",
                    # f"python3 /opt/dirsearch/dirsearch.py -u http://{self.target}:{port} -t 80 -e php -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -f -x 403,500 --plain-text-report {self.target}-Report/web/dirsearch-dlistmedium-{self.target}-{port}.log",
                    f"nikto -ask=no -host http://{self.target}:{port} >{self.target}-Report/web/niktoscan-{self.target}-{port}.txt 2>&1 &",
                )
            self.processes = commands
            # print(self.processes)

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
                whatweb_files = []
                cms_commands = []
                dir_list = [
                    d
                    for d in glob.iglob(f"{reportPath}", recursive=True)
                    if os.path.isdir(d)
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
                            "Nagios",
                        ]
                        with open(i, "r") as wwf:
                            for word in wwf:
                                fword = (
                                    word.replace("[", " ")
                                    .replace("]", " ")
                                    .replace(",", " ")
                                )
                                # print(fword)
                                for cms in cms_strings:
                                    if cms in fword:
                                        # print(cms)
                                        if "WordPress" in cms:
                                            wpscan_cmd = f"wpscan --no-update --url http://{self.target}:{http_port}/ --wp-content-dir wp-content --enumerate vp,vt,cb,dbe,u,m --plugins-detection aggressive | tee wpscan-{self.target}-{http_port}.log"
                                            # print(wpscan_cmd)
                                            cms_commands.append(wpscan_cmd)
                                        if "Drupal" in cms:
                                            drupal_cmd = f"droopescan scan drupal -u http://{self.target}:{http_port}/ -t 32 | tee drupalscan-{self.target}-{http_port}.log"
                                            cms_commands.append(drupal_cmd)
                                        if "Joomla" in cms:
                                            joomla_cmd = f"joomscan --url http://{self.target}:{http_port}/ -ec | tee joomlascan-{self.target}-{http_port}.log"
                                            cms_commands.append(joomla_cmd)
                                        if "Magento" in cms:
                                            magento_cmd = f"cd /opt/magescan && bin/magescan scan:all http://{self.target}:{http_port}/ | tee magentoscan-{self.target}-{http_port}.log && cd - &>/dev/null"
                                            cms_commands.append(magento_cmd)
                                        if "WebDAV" in cms:
                                            webdav_cmd = f"davtest -move -sendbd auto -url http://{self.target}:{http_port}/ | tee davtestscan-{self.target}-{http_port}.log"
                                            webdav_cmd2 = f"nmap -Pn -v -sV -p {http_port} --script=http-iis-webdav-vuln.nse -oA {self.target}-Report/nmap/webdav {self.target}"
                                            cms_commands.append(webdav_cmd)
                                            cms_commands.append(webdav_cmd2)

                sorted_commands = sorted(set(cms_commands))
                commands_to_run = []
                for i in sorted_commands:
                    commands_to_run.append(i)
                # print(commands_to_run)
                mpCmds = tuple(commands_to_run)
                # print(mpCmds)
                self.cms_processes = mpCmds
