#!/usr/bin/env python3

import os
from sty import fg
from autorecon.lib import nmapParser
from autorecon.lib import domainFinder
from subprocess import call
import glob
from autorecon.lib import vhostCrawl
from autorecon.lib import check_robots
from autorecon.utils import config_parser
from autorecon.utils import helper_lists
from collections.abc import Iterable
# import requests
# from bs4 import BeautifulSoup  # SoupStrainer


def flatten(lis):
    for item in lis:
        if isinstance(item, Iterable) and not isinstance(item, str):
            for x in flatten(item):
                yield x
        else:
            yield item


class EnumWeb:
    """The EnumWeb Class will enumeate all found open HTTP ports based off of nmap's initial
    scan results."""

    def __init__(self, target):
        self.target = target
        self.processes = ""
        self.cms_processes = ""
        self.proxy_processes = ""

    def check_links(self, hostnames: list, ports: list):
        import urllib.request
        import urllib.error
        from bs4 import BeautifulSoup
        import ssl
        found_links = []
        for host in hostnames:
            for port in ports:
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    url = urllib.request.urlopen(f'http://{host}:{port}/', context=ctx)
                    soup = BeautifulSoup(url, 'html.parser')
                    for _link in soup.findAll('a'):
                        try:
                            if host in _link.get('href'):
                                found_links.append(_link.get('href'))
                        except TypeError as err:
                            print(f"TypeError: {err}")
                            break
                    for _link in soup.findAll('img'):
                        try:
                            if host in _link.get('src'):
                                found_links.append(_link.get('src'))
                        except TypeError as err:
                            print(f"TypeError: {err}")
                            break
                except urllib.error.HTTPError as http_err:
                    print("HTTPError on http://{}:{}/ : {}".format(host, port, http_err))
                    break
                except urllib.error.ContentTooShortError as content_err:
                    print("ContentTooShortError on http://{}:{}/ : {}".format(host, port, content_err))
                    break
                except urllib.error.URLError as url_err:
                    print("URLError on http://{}:{}/ : {}".format(host, port, url_err))
                    break
        c = config_parser.CommandParser(f"{os.path.expanduser('~')}/.config/autorecon/config.yaml", self.target)
        if not os.path.exists(c.getPath("web", "aquatoneDir")):
            os.makedirs(c.getPath("web", "aquatoneDir"))
        with open(c.getPath("web", "aquatoneDirUrls"), 'a') as weblinks:
            if found_links:
                for l in found_links:
                    weblinks.write(l + '\n')
        # return found_links

    def Scan(self):
        """Enumerate Web Server ports based on nmaps output. This function will run the following tools;
        WhatWeb, WafW00f, Dirsearch, Nikto, and curl robots.txt"""
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        http_ports = np.http_ports
        system_type = np.os_system_type
        if len(http_ports) == 0:
            pass
        else:
            hl = helper_lists.IgnoreHttpPorts()
            _http_ports = [x for x in http_ports if x not in hl.ignore_http_ports]
            print(f"""{fg.li_cyan}Enumerating HTTP Ports! {fg.rs}""")
            c = config_parser.CommandParser(f"{os.path.expanduser('~')}/.config/autorecon/config.yaml", self.target)
            dn = domainFinder.DomainFinder(self.target)
            dn.getRedirect()
            hostnames = sorted(set(a.lower() for a in dn.redirect_hostname))
            if not os.path.exists(c.getPath("web", "webDir")):
                os.makedirs(c.getPath("web", "webDir"))
            if not os.path.exists(c.getPath("web", "aquatoneDir")):
                os.makedirs(c.getPath("web", "aquatoneDir"))
            commands = []
            another_array_of_hostnames = []
            if hostnames:
                for d in hostnames:
                    another_array_of_hostnames.append(d)
            if another_array_of_hostnames:
                vhc = vhostCrawl.checkSource(self.target, hostnames=another_array_of_hostnames)
                vhc.getLinks()
                htb_source_domains = vhc.htb_source_domains
                if htb_source_domains:
                    for d in htb_source_domains:
                        another_array_of_hostnames.append(d)

                sorted_hostnames = sorted(set(a.lower() for a in flatten(another_array_of_hostnames)))
                self.check_links(sorted_hostnames, http_ports)
                for hostname in sorted_hostnames:
                    for port in _http_ports:
                        commands.append(c.getCmd("web", "niktoHost", host=hostname, port=port))
                        commands.append(c.getCmd("web", "whatwebHttpHost", host=hostname, port=port))
                        commands.append(c.getCmd("web", "wafw00fHost", host=hostname, port=port))
                        commands.append(c.getCmd("web", "curlRobotsHost", host=hostname, port=port))
                        if system_type:
                            if system_type[0] == "Windows":
                                commands.append(c.getCmd("web", "dirsearchHttpHostDictWindows", host=hostname, port=port))
                                robots_check = check_robots.ParseRobots(self.target, port, althost=hostname)
                                disallowed_dirs = robots_check.interesting_dirs()
                                if disallowed_dirs:
                                    for _dir in disallowed_dirs:
                                        commands.append(c.getCmd("web", "dirsearchHostDisallowedWindows", host=hostname, port=port, dirname=_dir))
                            if system_type[0] == "Linux":
                                commands.append(c.getCmd("web", "dirsearchHttpHostDict", host=hostname, port=port))
                                robots_check = check_robots.ParseRobots(self.target, port, althost=hostname)
                                disallowed_dirs = robots_check.interesting_dirs()
                                if disallowed_dirs:
                                    for _dir in disallowed_dirs:
                                        commands.append(c.getCmd("web", "dirsearchHostDisallowed", host=hostname, port=port, dirname=_dir))
                        else:
                            commands.append(c.getCmd("web", "dirsearchHttpHostDict", host=hostname, port=port))
                            robots_check = check_robots.ParseRobots(self.target, port, althost=hostname)
                            disallowed_dirs = robots_check.interesting_dirs()
                            if disallowed_dirs:
                                for _dir in disallowed_dirs:
                                    commands.append(c.getCmd("web", "dirsearchHostDisallowed", host=hostname, port=port, dirname=_dir))

            else:
                for port in _http_ports:
                    commands.append(c.getCmd("web", "niktoTarget", port=port))
                    commands.append(c.getCmd("web", "whatwebHttpTarget", port=port))
                    commands.append(c.getCmd("web", "wafw00fTarget", port=port))
                    commands.append(c.getCmd("web", "curlRobotsTarget", port=port))
                    if system_type:
                        if system_type[0] == "Windows":
                            commands.append(c.getCmd("web", "dirsearchHttpTargetDictWindows", port=port))
                            robots_check = check_robots.ParseRobots(self.target, port)
                            disallowed_dirs = robots_check.interesting_dirs()
                            if disallowed_dirs:
                                for _dir in disallowed_dirs:
                                    commands.append(c.getCmd("web", "dirsearchDisallowedWindows", port=port, dirname=_dir))
                        if system_type[0] == "Linux":
                            commands.append(c.getCmd("web", "dirsearchHttpTargetDict", port=port))
                            robots_check = check_robots.ParseRobots(self.target, port)
                            disallowed_dirs = robots_check.interesting_dirs()
                            if disallowed_dirs:
                                for _dir in disallowed_dirs:
                                    commands.append(c.getCmd("web", "dirsearchDisallowed", port=port, dirname=_dir))
                    else:
                        commands.append(c.getCmd("web", "dirsearchHttpTargetDict", port=port))
                        robots_check = check_robots.ParseRobots(self.target, port)
                        disallowed_dirs = robots_check.interesting_dirs()
                        if disallowed_dirs:
                            for _dir in disallowed_dirs:
                                commands.append(c.getCmd("web", "dirsearchDisallowed", port=port, dirname=_dir))

            # sorted_cmds = sorted(set(commands), reverse=True)
            # commands_to_run = [i for i in sorted_cmds]
            self.processes = tuple(commands)

    def CMS(self):
        """If a valid CMS is found from initial Web Enumeration, more specifically, WhatWebs results, Then proceed to
        Enumerate the CMS further using Wpscan, Magescan, Nmap, Droopescan, Joomscan, and davtest, hydra, and will
        create a brute force bash script using Cewl, which can then be used by WpScan to try and brute force
        Users and passwords."""
        c = config_parser.CommandParser(f"{os.path.expanduser('~')}/.config/autorecon/config.yaml", self.target)
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        http_ports = np.http_ports
        dn = domainFinder.DomainFinder(self.target)
        dn.getRedirect()
        hostnames = dn.redirect_hostname
        another_array_of_hostnames = []
        if os.path.exists(c.getPath("web", "vhostnames")):
            with open(c.getPath("web", "vhostnames"), "r") as vhfile:
                lines = vhfile.readlines()
                for vh in lines:
                    another_array_of_hostnames.append(vh)
        if len(hostnames) != 0:
            for d in hostnames:
                another_array_of_hostnames.append(d)

        cms_commands = []
        if len(http_ports) == 0:
            pass
        else:
            for http_port in http_ports:
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
                        if "nmap" not in rf:
                            if "whatweb" in rf:
                                if str(http_port) in rf:
                                    whatweb_files.append(rf)
                                if len(another_array_of_hostnames) != 0:
                                    for host in another_array_of_hostnames:
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
                                                            wpscan_cmd = c.getCmd("web", "wpscanHttpHost", host=hn, httpPort=http_port)
                                                            cms_commands.append(wpscan_cmd)
                                                        if "Drupal" in cms:
                                                            if not os.path.exists(c.getPath("vuln", "vulnDir")):
                                                                os.makedirs(c.getPath("vuln", "vulnDir"))
                                                            cms_commands.append(c.getCmd("vuln", "searchsploit", strang=str(cms), name="Drupal"))
                                                            cms_commands.append(c.getCmd("web", "droopescanHost", host=hn, httpPort=http_port))
                                                        if "Joomla" in cms:
                                                            if not os.path.exists(c.getPath("vuln", "vulnDir")):
                                                                os.makedirs(c.getPath("vuln", "vulnDir"))
                                                            cms_commands.append(c.getCmd("vuln", "searchsploit", strang=str(cms), name="Joomla"))
                                                            cms_commands.append(c.getCmd("web", "joomscanHost", host=hn, httpPort=http_port))
                                                            cms_commands.append(c.getCmd("web", "joomlavsHost", host=hn, httpPort=http_port))
                                                        if "Magento" in cms:
                                                            if not os.path.exists(c.getPath("vuln", "vulnDir")):
                                                                os.makedirs(c.getPath("vuln", "vulnDir"))
                                                            cms_commands.append(c.getCmd("vuln", "searchsploit", strang=str(cms), name="Magento"))
                                                            cms_commands.append(c.getCmd("web", "magescanHost", host=hn, httpPort=http_port))
                                                        if "WebDAV" in cms or ("Microsoft-IIS 6.0" in cms):
                                                            if not os.path.exists(c.getPath("vuln", "vulnDir")):
                                                                os.makedirs(c.getPath("vuln", "vulnDir"))
                                                            cms_commands.append(c.getCmd("vuln", "searchsploit", strang=str(cms), name="WebDAV"))
                                                            webdav_cmd = c.getCmd("web", "davtestHost", host=hn)
                                                            webdav_cmd2 = c.getCmd("web", "webDavNmap", httpPort=http_port)
                                                            cms_commands.append(webdav_cmd)
                                                            cms_commands.append(webdav_cmd2)
                                                        if "tomcat" in cms:
                                                            if not os.path.exists(c.getPath("vuln", "vulnDir")):
                                                                os.makedirs(c.getPath("vuln", "vulnDir"))
                                                            cms_commands.append(c.getCmd("vuln", "searchsploit", strang=str(cms), name="tomcat"))
                                                            cms_commands.append(c.getCmd("web", "tomcatHydraHost", host=hn, httpPort=http_port))
                                                        if "Webmin" in cms:
                                                            if not os.path.exists(c.getPath("vuln", "vulnDir")):
                                                                os.makedirs(c.getPath("vuln", "vulnDir"))
                                                            cms_commands.append(c.getCmd("vuln", "searchsploit", strang=str(cms), name="Webmin"))
                                            else:
                                                if "WordPress" in cms:
                                                    wpscan_cmd = c.getCmd("web", "wpscanHttpTarget", httpPort=http_port)
                                                    cms_commands.append(wpscan_cmd)
                                                    manual_brute_force_script = f"""#!/bin/bash

if [[ -n $(grep -i "User(s) Identified" {c.getPath("web","wpscanHttpTarget", httpPort=http_port)}) ]]; then
    grep -w -A 100 "User(s)" {c.getPath("web","wpscanHttpTarget", httpPort=http_port)} | grep -w "[+]" | grep -v "WPVulnDB" | cut -d " " -f 2 >{c.getPath("web", "wordpressUsers")}
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
                                                    cms_commands.append(c.getCmd("web", "joomlavsTarget", httpPort=http_port))
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
                                                if "Webmin" in cms:
                                                    if not os.path.exists(c.getPath("vuln", "vulnDir")):
                                                        os.makedirs(c.getPath("vuln", "vulnDir"))
                                                    cms_commands.append(c.getCmd("vuln", "searchsploit", strang=str(cms), name="Webmin"))

                        except FileNotFoundError as fnf_error:
                            print(fnf_error)
                            continue

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
            c = config_parser.CommandParser(f"{os.path.expanduser('~')}/.config/autorecon/config.yaml", self.target)
            if not os.path.exists(c.getPath("proxy", "proxyDir")):
                os.makedirs(c.getPath("proxy", "proxyDir"))
            if not os.path.exists(c.getPath("proxy", "proxyWeb")):
                os.makedirs(c.getPath("proxy", "proxyWeb"))
            proxy_commands = []
            for proxy in proxy_ports:
                print(f"""{fg.li_cyan} Enumerating HTTP Ports Through Port: {proxy}, Running the following commands: {fg.rs}""")
                proxy_commands.append(c.getCmd("proxy", "whatwebProxyServer", proxy=proxy))
                if len(proxy_http_ports) != 0:
                    for proxy_http_port in proxy_http_ports:
                        proxy_commands.append(c.getCmd("proxy", "whatwebProxyHttpPorts", proxy=proxy, httpProxy=proxy_http_port))
                        proxy_commands.append(c.getCmd("proxy", "dirsearchHttpProxyPortsDict", proxy=proxy, httpProxy=proxy_http_port))
                        proxy_commands.append(c.getCmd("proxy", "niktoProxyHttpPort", proxy=proxy, httpProxy=proxy_http_port))

            self.proxy_processes = tuple(proxy_commands)

    # def getLinks(self):
    #     """This feature isn't full implemented yet and is just here to keep the other functions company ;)"""
    #     url = f"""http://{self.target}"""
    #     c = config_parser.CommandParser(f"{os.path.expanduser('~')}/.config/autorecon/config.yaml", self.target)
    #     page = requests.get(url)
    #     data = page.text
    #     soup = BeautifulSoup(data)
    #     links = []
    #     for link in soup.find_all("a"):
    #         links.append(link.get("href"))
    #     if len(links) != 0:
    #         try:
    #             with open(c.getPath("web", "weblinks"), "w") as l:
    #                 for link in links:
    #                     l.write(link)
    #         except FileNotFoundError as fnf_error:
    #             print(fnf_error)


class EnumWeb2:
    """Enumerate the web based on a custom url paths specified via the command line -w --web argument."""

    def __init__(self, web, target):
        self.web = web
        self.target = target
        self.processes = ""

    def ScanWebOption(self):
        """Enumerate Web Server ports based on nmaps output. This function will run the following tools;
        WhatWeb, WafW00f, Dirsearch, Nikto, and curl robots.txt
        This is almost identical to the normal web scan except it uses much larger wordlists
        """
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
            c = config_parser.CommandParser(f"{os.path.expanduser('~')}/.config/autorecon/config.yaml", self.target)
            commands = []
            if not os.path.exists(c.getPath("web", "webDir")):
                os.makedirs(c.getPath("web", "webDir"))
            if not os.path.exists(c.getPath("web", "aquatoneDir")):
                os.makedirs(c.getPath("web", "aquatoneDir"))
            if hostnames:
                sorted_hostnames = sorted(set(hostnames))
                for hostname in sorted_hostnames:
                    for port in http_ports:
                        commands.append(c.getCmd("web", "whatwebHttpHost", host=hostname, port=port))
                        # commands.append(c.getCmd("web", "eyewitnessHost", host=hostname, port=port))
                        # commands.append(c.getCmd("web", "wafw00fHost", host=hostname, port=port))
                        # commands.append(c.getCmd("web", "curlRobotsHost", host=hostname, port=port))
                        commands.append(c.getCmd("web", "dirsearchHttpHostDListMed", host=hostname, port=port, url=self.web))
                        commands.append(c.getCmd("web", "dirsearchHttpHostRaftLargeFiles", host=hostname, port=port, url=self.web))
                        commands.append(c.getCmd("web", "dirsearchHttpHostRaftLargeDirs", host=hostname, port=port, url=self.web))
                        commands.append(c.getCmd("web", "dirsearchHttpHostForeign", host=hostname, port=port, url=self.web))
                        # commands.append(c.getCmd("web", "niktoHost", host=hostname, port=port))

            else:
                for port in http_ports:
                    commands.append(c.getCmd("web", "whatwebHttpTarget", port=port))
                    # commands.append(c.getCmd("web", "eyewitnessTarget", port=port))
                    # commands.append(c.getCmd("web", "wafw00fTarget", port=port))
                    # commands.append(c.getCmd("web", "curlRobotsTarget", port=port))
                    commands.append(c.getCmd("web", "dirsearchHttpTargetDListMed", port=port, url=self.web))
                    commands.append(c.getCmd("web", "dirsearchHttpTargetRaftLargeFiles", port=port, url=self.web))
                    commands.append(c.getCmd("web", "dirsearchHttpTargetRaftLargeDirs", port=port, url=self.web))
                    commands.append(c.getCmd("web", "dirsearchHttpTargetForeign", port=port, url=self.web))
                    # commands.append(c.getCmd("web", "niktoHost", port=port))

            self.processes = tuple(commands)


# class PrecisionCrawl:
#     """This Class hasn't been completed yet, but will ultimately be used to crawl urls recursively or something
#     useful."""

#     def __init__(self, target):
#         self.target = target

#     def snipe(self):
#         c = config_parser.CommandParser(f"{os.path.expanduser('~')}/.config/autorecon/config.yaml", self.target)
#         hl = helper_lists.ignoreURLS()
#         ignore_urls = hl.ignore_urls
#         php_urls = []
#         if os.path.exists(c.getPath("web", "aquatoneDirUrls")):
#             check_lines = f"""wc -l {c.getPath("web","aquatoneDirUrls")} | cut -d ' ' -f 1"""
#             num_urls = check_output(check_lines, stderr=STDOUT, shell=True).rstrip()
#             if int(num_urls) < 150 and (int(num_urls) != 0):
#                 try:
#                     with open(c.getPath("web", "aquatoneDirUrls"), "r") as found_urls:
#                         for line in found_urls:
#                             url = line.rstrip()
#                             if (
#                                 url.endswith("/")
#                                 and (url not in ignore_urls)
#                                 and ("index.php" not in url)
#                                 and (url.endswith(".php/") is False)
#                             ):
#                                 php_urls.append(url)
#                 except FileNotFoundError as fnf_error:
#                     print(fnf_error)
#                     pass
#                 if len(php_urls) != 0 and (len(php_urls) < 10):
#                     for i in php_urls:
#                         print(i)
