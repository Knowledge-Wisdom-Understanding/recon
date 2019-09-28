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
from utils import config_parser


class EnumWeb:
    """The EnumWeb Class will enumeate all found open HTTP ports based off of nmap's initial
    scan results."""

    def __init__(self, target):
        self.target = target
        self.processes = ""
        self.cms_processes = ""
        self.proxy_processes = ""

    def Scan(self):
        """Enumerate Web Server ports based on nmaps output. This function will run the following tools;
        WhatWeb, WafW00f, Dirsearch, EyeWitness, Nikto, and curl robots.txt"""
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        http_ports = np.http_ports
        if len(http_ports) == 0:
            pass
        else:
            print(f"""{fg.li_cyan}Enumerating HTTP Ports! {fg.rs}""")
            c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
            dn = domainFinder.DomainFinder(self.target)
            dn.getRedirect()
            hostnames = dn.redirect_hostname
            if not os.path.exists(c.getPath("web", "webDir")):
                os.makedirs(c.getPath("web", "webDir"))
            if not os.path.exists(c.getPath("web", "aquatoneDir")):
                os.makedirs(c.getPath("web", "aquatoneDir"))
            dc = dnsCrawl.checkSource(self.target)
            dc.getLinks()
            htb_source_domains = dc.htb_source_domains
            commands = []
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
                        if not os.path.exists(c.getPath("web", "eyewitnessDirHost", host=hostname, port=port)):
                            os.makedirs(c.getPath("web", "eyewitnessDirHost", host=hostname, port=port))

                        commands.append(c.getCmd("web", "whatwebHttpHost", host=hostname, port=port))
                        commands.append(c.getCmd("web", "eyewitnessHost", host=hostname, port=port))
                        commands.append(c.getCmd("web", "wafw00fHost", host=hostname, port=port))
                        commands.append(c.getCmd("web", "curlRobotsHost", host=hostname, port=port))
                        commands.append(c.getCmd("web", "dirsearchHttpHostDict", host=hostname, port=port))
                        commands.append(c.getCmd("web", "dirsearchHttpHostBig", host=hostname, port=port))
                        commands.append(c.getCmd("web", "niktoHost", host=hostname, port=port))
            else:
                for port in http_ports:
                    if not os.path.exists(c.getPath("web", "eyewitnessDirTarget", port=port)):
                        os.makedirs(c.getPath("web", "eyewitnessDirTarget", port=port))

                    commands.append(c.getCmd("web", "whatwebHttpTarget", port=port))
                    commands.append(c.getCmd("web", "eyewitnessTarget", port=port))
                    commands.append(c.getCmd("web", "wafw00fTarget", port=port))
                    commands.append(c.getCmd("web", "curlRobotsTarget", port=port))
                    commands.append(c.getCmd("web", "dirsearchHttpTargetBig", port=port))
                    commands.append(c.getCmd("web", "dirsearchHttpTargetDict", port=port))
                    commands.append(c.getCmd("web", "niktoTarget", port=port))

            # sorted_cmds = sorted(set(commands), reverse=True)
            # commands_to_run = [i for i in sorted_cmds]
            self.processes = tuple(commands)

    def ScanWebOption(self):
        """Enumerate Web Server ports based on nmaps output. This function will run the following tools;
        WhatWeb, WafW00f, Dirsearch, EyeWitness, Nikto, and curl robots.txt
        This is almost identical to the normal web scan except, it uses much larger wordlists
         and doesn't run EyeWitnesss Since that tool is run on the intended default
        Original Scan option."""
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        http_ports = np.http_ports
        dn = domainFinder.DomainFinder(self.target)
        dn.getRedirect()
        hostnames = dn.redirect_hostname
        if len(http_ports) == 0:
            pass
        else:
            reset = fg.rs
            print(f"""{fg.li_cyan}Enumerating HTTP Ports, Running the following commands: {reset}""")
            c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
            commands = []
            if not os.path.exists(c.getPath("web", "webDir")):
                os.makedirs(c.getPath("web", "webDir"))
            if not os.path.exists(c.getPath("web", "aquatoneDir")):
                os.makedirs(c.getPath("web", "aquatoneDir"))
            if hostnames:
                sorted_hostnames = sorted(set(hostnames))
                for hostname in sorted_hostnames:
                    for port in http_ports:
                        if not os.path.exists(c.getPath("web", "eyewitnessDirHost", host=hostname, port=port)):
                            os.makedirs(c.getPath("web", "eyewitnessDirHost", host=hostname, port=port))

                        commands.append(c.getCmd("web", "whatwebHttpHost", host=hostname, port=port))
                        commands.append(c.getCmd("web", "eyewitnessHost", host=hostname, port=port))
                        commands.append(c.getCmd("web", "wafw00fHost", host=hostname, port=port))
                        commands.append(c.getCmd("web", "curlRobotsHost", host=hostname, port=port))
                        commands.append(c.getCmd("web", "dirsearchHttpHostDListMed", host=hostname, port=port))
                        commands.append(c.getCmd("web", "dirsearchHttpHostRaftLargeFiles", host=hostname, port=port))
                        commands.append(c.getCmd("web", "dirsearchHttpHostRaftLargeDirs", host=hostname, port=port))
                        commands.append(c.getCmd("web", "dirsearchHttpHostForeign", host=hostname, port=port))
                        commands.append(c.getCmd("web", "niktoHost", host=hostname, port=port))

            else:
                for port in http_ports:
                    if not os.path.exists(c.getPath("web", "eyewitnessDirTarget", port=port)):
                        os.makedirs(c.getPath("web", "eyewitnessDirTarget", port=port))

                    commands.append(c.getCmd("web", "whatwebHttpTarget", port=port))
                    commands.append(c.getCmd("web", "eyewitnessTarget", port=port))
                    commands.append(c.getCmd("web", "wafw00fTarget", port=port))
                    commands.append(c.getCmd("web", "curlRobotsTarget", port=port))
                    commands.append(c.getCmd("web", "dirsearchHttpTargetDListMed", port=port))
                    commands.append(c.getCmd("web", "dirsearchHttpTargetRaftLargeFiles", port=port))
                    commands.append(c.getCmd("web", "dirsearchHttpTargetRaftLargeDirs", port=port))
                    commands.append(c.getCmd("web", "dirsearchHttpTargetForeign", port=port))
                    commands.append(c.getCmd("web", "niktoHost", port=port))

            self.processes = tuple(commands)

    def CMS(self):
        """If a valid CMS is found from initial Web Enumeration, more specifically, WhatWebs results, Then proceed to
        Enumerate the CMS further using Wpscan, Magescan, Nmap, Droopescan, Joomscan, and davtest, hydra, and will
        create a brute force bash script using Cewl, which will then be used by WpScan to try and brute force
        Users and passwords."""
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        http_ports = np.http_ports
        cms_commands = []
        if len(http_ports) == 0:
            pass
        else:
            c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
            for http_port in http_ports:
                whatweb_files = []
                dir_list = [
                    d
                    for d in glob.iglob(c.getPath("report", "reportGlob"), recursive=True)
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
                            "Microsoft-IIS 6.0",
                            "Drupal",
                            "Joomla",
                        ]
                        try:
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
                                                wpscan_cmd = c.getCmd("web", "wpscanHttpTarget", httpPort=http_port)
                                                cms_commands.append(wpscan_cmd)
                                                manual_brute_force_script = f"""
    #!/bin/bash

    if [[ -n $(grep -i "User(s) Identified" {c.getPath("web","wpscanHttpTarget", httpPort=http_port)}) ]]; then
        grep -w -A 100 "User(s)" {c.getPath("web","wpscanHttpTarget", httpPort=http_port)} | grep -w "[+]" | cut -d " " -f 2 | head -n -7 >{c.getPath("web", "wordpressUsers")}
        {c.getCmd("web", "CewlWeb", httpPort=http_port)}
        sleep 10
        echo "Adding John Rules to Cewl Wordlist!"
        {c.getCmd("web", "cewl2John")}
        sleep 3
        # brute force again with wpscan
        {c.getCmd("web", "wpscanCewlBrute", httpPort=http_port)}
        sleep 1
        if grep -i "No Valid Passwords Found" {c.getPath("web", "wpscanCewlBrute")}; then
            if [[ -s {c.getPath("web", "johnCewlWordlist")} ]]; then
                {c.getCmd("web", "wpscanCewlJohnBrute", httpPort=http_port)}
            else
                echo "John wordlist is empty :("
            fi
            sleep 1
            if grep -i "No Valid Passwords Found" {c.getPath("web", "wordpressJohnCewlBrute")}; then
                {c.getCmd("web", "wpscanFastTrackBrute", httpPort=http_port)}
            fi
        fi
    fi
                                                """
                                                try:
                                                    with open(c.getPath("web", "wpscanBashBruteScript"), "w") as wpb:
                                                        print("Creating wordpress Brute Force Script...")
                                                        wpb.write(manual_brute_force_script)
                                                    call(f"""chmod +x {c.getPath("web", "wpscanBashBruteScript")}""", shell=True)
                                                except FileNotFoundError as fnf_error:
                                                    print(fnf_error)

                                            if "Drupal" in cms:
                                                if not os.path.exists(c.getPath("vuln", "vulnDir")):
                                                    os.makedirs(c.getPath("vuln", "vulnDir"))
                                                cms_commands.append(c.getCmd("vuln", "searchsploit", strang=str(cms), name="Drupal"))
                                                cms_commands.append(c.getCmd("web", "droopescan", httpPort=http_port))
                                            if "Joomla" in cms:
                                                if not os.path.exists(c.getPath("vuln", "vulnDir")):
                                                    os.makedirs(c.getPath("vuln", "vulnDir"))
                                                cms_commands.append(c.getCmd("vuln", "searchsploit", strang=str(cms), name="Joomla"))
                                                cms_commands.append(c.getCmd("web", "joomscan", httpPort=http_port))
                                            if "Magento" in cms:
                                                if not os.path.exists(c.getPath("vuln", "vulnDir")):
                                                    os.makedirs(c.getPath("vuln", "vulnDir"))
                                                cms_commands.append(c.getCmd("vuln", "searchsploit", strang=str(cms), name="Magento"))
                                                cms_commands.append(c.getCmd("web", "magescan", httpPort=http_port))
                                            if "WebDAV" in cms or ("Microsoft-IIS 6.0" in cms):
                                                if not os.path.exists(c.getPath("vuln", "vulnDir")):
                                                    os.makedirs(c.getPath("vuln", "vulnDir"))
                                                cms_commands.append(c.getCmd("vuln", "searchsploit", strang=str(cms), name="WebDAV"))
                                                webdav_cmd = c.getCmd("web", "davtest")
                                                webdav_cmd2 = c.getCmd("web", "webDavNmap", httpPort=http_port)
                                                cms_commands.append(webdav_cmd)
                                                cms_commands.append(webdav_cmd2)
                                            if "tomcat" in cms:
                                                if not os.path.exists(c.getPath("vuln", "vulnDir")):
                                                    os.makedirs(c.getPath("vuln", "vulnDir"))
                                                cms_commands.append(c.getCmd("vuln", "searchsploit", strang=str(cms), name="tomcat"))
                                                cms_commands.append(c.getCmd("web", "tomcatHydra", httpPort=http_port))

                        except FileNotFoundError as fnf_error:
                            print(fnf_error)
                            exit()
            sorted_commands = sorted(set(cms_commands))
            commands_to_run = [i for i in sorted_commands]
            self.cms_processes = tuple(commands_to_run)

    def proxyScan(self):
        """This is the Web Proxy scan function that is called by lib/enumProxy.py.
        This function will attempt to run, dirsearch, whatweb, and nikto"""
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        npp = nmapParser.NmapParserFunk(self.target)
        npp.openProxyPorts()
        proxy_http_ports = npp.proxy_http_ports
        proxy_ports = np.proxy_ports
        if len(proxy_http_ports) == 0:
            pass
        else:
            c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
            if not os.path.exists(c.getPath("proxy", "proxyDir")):
                os.makedirs(c.getPath("proxy", "proxyDir"))
            if not os.path.exists(c.getPath("proxy", "proxyWeb")):
                os.makedirs(c.getPath("proxy", "proxyWeb"))
            proxy_commands = []
            for proxy in proxy_ports:
                print(f"""{fg.li_cyan} Enumerating HTTP Ports Through Port: {proxy}, Running the following commands: {fg.rs}""")
                if not os.path.exists(c.getPath("proxy", "eyewitnessDirPT", proxy=proxy)):
                    os.makedirs(c.getPath("proxy", "eyewitnessDirPT", proxy=proxy))
                proxy_commands.append(c.getCmd("proxy", "eyewitnessProxyServer", proxy=proxy))
                proxy_commands.append(c.getCmd("proxy", "whatwebProxyServer", proxy=proxy))
                if len(proxy_http_ports) != 0:
                    for proxy_http_port in proxy_http_ports:
                        proxy_commands.append(c.getCmd("proxy", "whatwebProxyHttpPorts", proxy=proxy, httpProxy=proxy_http_port))
                        proxy_commands.append(c.getCmd("proxy", "dirsearchHttpProxyPortsDict", proxy=proxy, httpProxy=proxy_http_port))
                        proxy_commands.append(c.getCmd("proxy", "dirsearchHttpProxyPortsBig", proxy=proxy, httpProxy=proxy_http_port))
                        proxy_commands.append(c.getCmd("proxy", "niktoProxyHttpPort", proxy=proxy, httpProxy=proxy_http_port))

            self.proxy_processes = tuple(proxy_commands)

    def getLinks(self):
        """This feature isn't full implemented yet and is just here to keep the other functions company ;)"""
        url = f"""http://{self.target}"""
        c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
        page = requests.get(url)
        data = page.text
        soup = BeautifulSoup(data)
        links = []
        for link in soup.find_all("a"):
            links.append(link.get("href"))
        if len(links) != 0:
            try:
                with open(c.getPath("web", "weblinks"), "w") as l:
                    for link in links:
                        l.write(link)
            except FileNotFoundError as fnf_error:
                print(fnf_error)
