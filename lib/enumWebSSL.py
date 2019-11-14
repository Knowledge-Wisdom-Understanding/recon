#!/usr/bin/env python3

import os
from sty import fg
from lib import nmapParser
from lib import dnsenum
from utils import peaceout_banner
import glob
from utils import config_parser
from subprocess import call
from utils import run_commands


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
        heartbleed = df.heartbleed
        hostnames = df.hostnames
        ssl_ports = np.ssl_ports
        if len(ssl_ports) == 0:
            pass
        else:
            c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
            if not os.path.exists(c.getPath("webSSL", "webSSLDir")):
                os.makedirs(c.getPath("webSSL", "webSSLDir"))
            if not os.path.exists(c.getPath("web", "aquatoneDir")):
                os.makedirs(c.getPath("web", "aquatoneDir"))
            print(fg.li_cyan + "Enumerating HTTPS/SSL Ports" + fg.rs)
            if heartbleed is True:
                rc = run_commands.RunCommands(self.target)
                be_mine = peaceout_banner.heartbleed(self.target)
                be_mine.bleedOut()
                for sslport in ssl_ports:
                    rc.loginator(c.getCmd("webSSL", "heartbleed", port=sslport))
                    call(c.getCmd("webSSL", "heartbleed", port=sslport), shell=True)
            commands = []
            if len(hostnames) == 0:
                for sslport in ssl_ports:
                    commands.append(c.getCmd("webSSL", "whatwebSSLTarget", port=sslport))
                    commands.append(c.getCmd("webSSL", "eyewitnessSSLTarget", port=sslport))
                    commands.append(c.getCmd("webSSL", "wafw00fSSLTarget", port=sslport))
                    commands.append(c.getCmd("webSSL", "curlRobotsSSLTarget", port=sslport))
                    commands.append(c.getCmd("webSSL", "dirsearchSSLTargetBig", port=sslport))
                    commands.append(c.getCmd("webSSL", "dirsearchSSLTargetDict", port=sslport))
                    commands.append(c.getCmd("webSSL", "niktoSSLTarget", port=sslport))
            else:
                for sslport in ssl_ports:
                    for host in hostnames:
                        commands.append(c.getCmd("webSSL", "whatwebSSLHost", host=host, port=sslport))
                        commands.append(c.getCmd("webSSL", "eyewitnessSSLHost", host=host, port=sslport))
                        commands.append(c.getCmd("webSSL", "wafw00fSSLHost", host=host, port=sslport))
                        commands.append(c.getCmd("webSSL", "curlRobotsSSLHost", host=host, port=sslport))
                        commands.append(c.getCmd("webSSL", "dirsearchSSLHostDict", host=host, port=sslport))
                        commands.append(c.getCmd("webSSL", "dirsearchSSLHostBig", host=host, port=sslport))
                        commands.append(c.getCmd("webSSL", "niktoSSLHost", host=host, port=sslport))

            self.processes = tuple(commands)

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
            c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
            if not os.path.exists(c.getPath("proxy", "proxyDir")):
                os.makedirs(c.getPath("proxy", "proxyDir"))
            if not os.path.exists(c.getPath("proxy", "proxyWebSSL")):
                os.makedirs(c.getPath("proxy", "proxyWebSSL"))
            proxy_commands = []
            for proxy in proxy_ports:
                print(f"""{fg.li_cyan} Enumerating HTTPS Ports Through {proxy}, Running the following commands: {fg.rs}""")
                for proxy_ssl_port in proxy_ssl_ports:
                    proxy_commands.append(c.getCmd("proxySSL", "whatwebSSLProxy", proxy=proxy, proxySSLPort=proxy_ssl_port))
                    proxy_commands.append(c.getCmd("proxySSL", "dirsearchProxySSLDict", proxySslPort=proxy_ports, proxy=proxy_ssl_port))
                    proxy_commands.append(c.getCmd("proxySSL", "dirsearchProxySSLBig", proxySSLPort=proxy_ports, proxy=proxy_ssl_port))
                    proxy_commands.append(c.getCmd("proxySSL", "niktoProxySSL", proxySSLPort=proxy, proxy=proxy_ssl_port))

            self.proxy_processes = tuple(proxy_commands)
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
            c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
            for ssl_port in ssl_ports:
                whatweb_files = []
                whatweb_hostnames = []
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
                        if "whatweb" in rf:
                            if str(ssl_port) in rf:
                                whatweb_files.append(rf)
                            if len(hostnames) != 0:
                                for host in hostnames:
                                    if host in rf:
                                        whatweb_hostnames.append(host)
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
                            "Webmin",
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
                                            if len(whatweb_hostnames) != 0:
                                                for hn in whatweb_hostnames:
                                                    if hn in i:
                                                        if "WordPress" in cms:
                                                            if not os.path.exists(c.getPath("vuln", "vulnDir")):
                                                                os.makedirs(c.getPath("vuln", "vulnDir"))
                                                            cms_commands.append(c.getCmd("vuln", "searchsploit", strang=str(cms), name="WordPress"))
                                                            cms_commands.append(c.getCmd("webSSL", "wpscanSSLHost", host=hn, sslPort=ssl_port))
                                                        if "Drupal" in cms:
                                                            if not os.path.exists(c.getPath("vuln", "vulnDir")):
                                                                os.makedirs(c.getPath("vuln", "vulnDir"))
                                                            cms_commands.append(c.getCmd("vuln", "searchsploit", strang=str(cms), name="Drupal"))
                                                            cms_commands.append(c.getCmd("webSSL", "droopescanSSLHost", host=hn, sslPort=ssl_port))
                                                        if "Joomla" in cms:
                                                            if not os.path.exists(c.getPath("vuln", "vulnDir")):
                                                                os.makedirs(c.getPath("vuln", "vulnDir"))
                                                            cms_commands.append(c.getCmd("vuln", "searchsploit", strang=str(cms), name="Joomla"))
                                                            cms_commands.append(c.getCmd("webSSL", "joomscanHost", host=hn, sslPort=ssl_port))
                                                            cms_commands.append(c.getCmd("webSSL", "joomlavsSSLHost", host=hn, sslPort=ssl_port))
                                                        if "Magento" in cms:
                                                            if not os.path.exists(c.getPath("vuln", "vulnDir")):
                                                                os.makedirs(c.getPath("vuln", "vulnDir"))
                                                            cms_commands.append(c.getCmd("vuln", "searchsploit", strang=str(cms), name="Magento"))
                                                            cms_commands.append(c.getCmd("webSSL", "magescanHost", host=hn, sslPort=ssl_port))
                                                        if "WebDAV" in cms:
                                                            if not os.path.exists(c.getPath("vuln", "vulnDir")):
                                                                os.makedirs(c.getPath("vuln", "vulnDir"))
                                                            cms_commands.append(c.getCmd("vuln", "searchsploit", strang=str(cms), name="WebDAV"))
                                                            cms_commands.append(c.getCmd("webSSL", "davtestHost", host=hn))
                                                        if "Webmin" in cms:
                                                            if not os.path.exists(c.getPath("vuln", "vulnDir")):
                                                                os.makedirs(c.getPath("vuln", "vulnDir"))
                                                            cms_commands.append(c.getCmd("vuln", "searchsploit", strang=str(cms), name="Webmin"))
                                            else:
                                                if "WordPress" in cms:
                                                    cms_commands.append(c.getCmd("webSSL", "wpscanSSLTarget", sslPort=ssl_port))
                                                    manual_brute_force_script = f"""#!/bin/bash

if [[ -n $(grep -i "User(s) Identified" {c.getPath("webSSL", "wpscanSSL", sslPort=ssl_port)}) ]]; then
    grep -w -A 100 "User(s)" {c.getPath("webSSL", "wpscanSSL", sslPort=ssl_port)} | grep -w "[+]" | grep -v "WPVulnDB" | cut -d " " -f 2 | head -n -7 >{c.getPath("webSSL", "wpUsers")}
    {c.getCmd("webSSL", "cewlSSLTarget", sslPort=ssl_port)}
    sleep 10
    echo "Adding John Rules to Cewl Wordlist!"
    {c.getCmd("webSSL", "johnCewl")}
    sleep 3
    # brute force again with wpscan
    {c.getCmd("webSSL", "wpscanCewlBruteTarget", sslPort=ssl_port)}
    sleep 1
    if grep -i "No Valid Passwords Found" {c.getPath("webSSL", "wpscanCewlBruteReport")}; then
        if [ -s {c.getPath("webSSL", "cewlJohnList")} ]; then
            {c.getCmd("webSSL", "wpscanJohnCewlBruteTarget", sslPort=ssl_port)}
        else
            echo "John wordlist is empty :("
        fi
        sleep 1
        if grep -i "No Valid Passwords Found" {c.getPath("webSSL", "wordpressJohnCewlBrute")}; then
            {c.getCmd("webSSL", "wpscanFastTrackHost", sslPort=ssl_port)}
        fi
    fi
fi
                                                """
                                                    try:
                                                        with open(c.getPath("webSSL", "wordpressBruteBashScript"), "w") as wpb:
                                                            print("Creating wordpress Brute Force Script...")
                                                            wpb.write(manual_brute_force_script)
                                                        call(f"""chmod +x {c.getPath("webSSL", "wordpressBruteBashScript")}""", shell=True)
                                                    except FileNotFoundError as fnf_error:
                                                        print(fnf_error)
                                                        continue
                                                if "Drupal" in cms:
                                                    if not os.path.exists(c.getPath("vuln", "vulnDir")):
                                                        os.makedirs(c.getPath("vuln", "vulnDir"))
                                                    cms_commands.append(c.getCmd("vuln", "searchsploit", strang=str(cms), name="Drupal"))
                                                    cms_commands.append(c.getCmd("webSSL", "droopescanSSLHost", sslPort=ssl_port))
                                                if "Joomla" in cms:
                                                    if not os.path.exists(c.getPath("vuln", "vulnDir")):
                                                        os.makedirs(c.getPath("vuln", "vulnDir"))
                                                    cms_commands.append(c.getCmd("vuln", "searchsploit", strang=str(cms), name="Joomla"))
                                                    cms_commands.append(c.getCmd("webSSL", "joomscanTarget", sslPort=ssl_port))
                                                    cms_commands.append(c.getCmd("webSSL", "joomlavsSSLTarget", sslPort=ssl_port))
                                                if "Magento" in cms:
                                                    if not os.path.exists(c.getPath("vuln", "vulnDir")):
                                                        os.makedirs(c.getPath("vuln", "vulnDir"))
                                                    cms_commands.append(c.getCmd("vuln", "searchsploit", strang=str(cms), name="Magento"))
                                                    cms_commands.append(c.getCmd("webSSL", "magescanTarget", sslPort=ssl_port))
                                                if "WebDAV" in cms:
                                                    if not os.path.exists(c.getPath("vuln", "vulnDir")):
                                                        os.makedirs(c.getPath("vuln", "vulnDir"))
                                                    cms_commands.append(c.getCmd("vuln", "searchsploit", strang=str(cms), name="WebDAV"))
                                                    cms_commands.append(c.getCmd("webSSL", "davtestTarget"))
                                                    cms_commands.append(c.getCmd("webSSL", "nmapWebDav", sslPot=ssl_port))
                                                if "Webmin" in cms:
                                                    if not os.path.exists(c.getPath("vuln", "vulnDir")):
                                                        os.makedirs(c.getPath("vuln", "vulnDir"))
                                                    cms_commands.append(c.getCmd("vuln", "searchsploit", strang=str(cms), name="Webmin"))
                        except FileNotFoundError as fnf:
                            print(fnf)
                            continue

            sorted_commands = sorted(set(cms_commands))
            commands_to_run = []
            for i in sorted_commands:
                commands_to_run.append(i)
            mpCmds = tuple(commands_to_run)
            self.cms_processes = mpCmds


class EnumWebSSL2:
    """Enumerate the web based on a custom url paths specified via the command line -w --web argument."""

    def __init__(self, web, target):
        self.web = web
        self.target = target
        self.processes = ""

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
            commands = []
            c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
            if not os.path.exists(c.getPath("webSSL", "webSSLDir")):
                os.makedirs(c.getPath("webSSL", "webSSLDir"))
            if not os.path.exists(c.getPath("web", "aquatoneDir")):
                os.makedirs(c.getPath("web", "aquatoneDir"))
            print(fg.li_cyan + "Enumerating HTTPS/SSL Ports, Running the following commands:" + fg.rs)
            if len(hostnames) == 0:
                for sslport in ssl_ports:
                    commands.append(c.getCmd("webSSL", "whatwebSSLTarget", port=sslport))
                    # commands.append(c.getCmd("webSSL", "eyewitnessSSLTarget", port=sslport))
                    # commands.append(c.getCmd("webSSL", "wafw00fSSLTarget", port=sslport))
                    # commands.append(c.getCmd("webSSL", "curlRobotsSSLTarget", port=sslport))
                    commands.append(c.getCmd("webSSL", "dirsearchSSLTargetDListMed", port=sslport, url=self.web))
                    commands.append(c.getCmd("webSSL", "dirsearchSSLTargetRaftLargeFiles", port=sslport, url=self.web))
                    commands.append(c.getCmd("webSSL", "dirsearchSSLTargetRaftLargeDirs", port=sslport, url=self.web))
                    commands.append(c.getCmd("webSSL", "dirsearchSSLTargetForeign", port=sslport, url=self.web))
                    # commands.append(c.getCmd("webSSL", "niktoSSLHost", port=sslport))
            else:
                for sslport in ssl_ports:
                    for hostname in hostnames:
                        commands.append(c.getCmd("webSSL", "whatwebSSLHost", host=hostname, port=sslport))
                        # commands.append(c.getCmd("webSSL", "eyewitnessSSLHost", host=hostname, port=sslport))
                        # commands.append(c.getCmd("webSSL", "wafw00fSSLHost", host=hostname, port=sslport))
                        # commands.append(c.getCmd("webSSL", "curlRobotsSSLHost", host=hostname, port=sslport))
                        commands.append(c.getCmd("webSSL", "dirsearchSSLHostDListMed", host=hostname, port=sslport, url=self.web))
                        commands.append(c.getCmd("webSSL", "dirsearchSSLHostRaftLargeFiles", host=hostname, port=sslport, url=self.web))
                        commands.append(c.getCmd("webSSL", "dirsearchSSLHostRaftLargeDirs", host=hostname, port=sslport, url=self.web))
                        commands.append(c.getCmd("webSSL", "dirsearchSSLHostForeign", host=hostname, port=sslport, url=self.web))
                        # commands.append(c.getCmd("webSSL", "niktoSSLHost", host=hostname, port=sslport))

            self.processes = tuple(commands)
