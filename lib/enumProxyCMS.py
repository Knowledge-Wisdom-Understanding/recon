#!/usr/bin/env python3

import os
from sty import fg, bg, ef, rs
from lib import nmapParser
from utils import helper_lists
from subprocess import call
import glob
from utils import config_parser


class EnumProxyCMS:
    """EnumProxyCMS will enumerate any found Content Management Systems found running on webservers that were
    discovered through a http-proxy port using proxychains and other cool tools that you will see being used in the code
    if you take the time to read through it."""

    def __init__(self, target):
        self.target = target
        self.processes = ""
        self.cms_processes = ""
        self.proxy_processes = ""
        self.redirect_hostname = []

    def proxyCMS(self):
        """If a Content Management System is discovered on the web from enumProxy's output, Then proceed to try and enumerate the CMS further.
        CMS Scanners to be scanned are limited to: Drupal, Wordpress, Joomla, Magento, Tomcat, and Apache WebDav"""
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        npp = nmapParser.NmapParserFunk(self.target)
        npp.openProxyPorts()
        proxy_http_ports = npp.proxy_http_ports
        proxy_ports = np.proxy_ports
        teal = fg.li_cyan
        hasPrinted = False
        cms_commands = []
        cms_counter = 0
        reset = fg.rs
        if len(proxy_http_ports) == 0:
            pass
        if len(proxy_ports) == 0:
            pass
        else:
            c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
            for proxy_http_port in proxy_http_ports:
                whatweb_files = []
                wordpress_url = []
                wp = helper_lists.Wordpress(self.target)
                wordpressDirs = wp.wordpress_dirs
                if os.path.exists(c.getPath("proxy", "aquatoneDirProxyUrls")):
                    try:
                        with open(c.getPath("proxy", "aquatoneDirProxyUrls"), "r") as purls:
                            for url in purls:
                                uline = url.rstrip()
                                for word in wordpressDirs:
                                    if word in uline:
                                        wordpress_url.append(uline)
                    except FileNotFoundError as fnf_error:
                        print(fnf_error)
                        exit()
                    sorted_wp_dirs = sorted(set(wordpress_url))
                    count = 0
                    if len(sorted_wp_dirs) != 0:
                        for wpdir in sorted_wp_dirs:
                            count += 1
                            try:
                                # whatweb_proxy_cmd = f"""whatweb -v -a 3 --proxy {self.target}:{proxy_ports[0]} {wpdir} > {c.getPath("reportDir")}/proxy/web/whatweb-proxy-{proxy_http_port}-{count}.txt"""
                                whatweb_proxy_cmd = c.getCmd("proxy", "whatwebProxy", proxyPorts=proxy_ports[0], wordpressDirs=wpdir, httpProxy=proxy_http_port, count=count)
                                call(whatweb_proxy_cmd, shell=True)
                                if count >= 2:
                                    break
                            except OSError:
                                pass

                dir_list = [
                    d
                    for d in glob.iglob(c.getPath("proxy", "proxyGlob"), recursive=True)
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
                                if str(proxy_http_port) in rf:
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
                                        if "WordPress" in cms and not hasPrinted:
                                            print(f"{teal}Found WordPress!{reset}")
                                            cms_counter += 1
                                            if len(sorted_wp_dirs) != 0:
                                                wpscan_cmd = c.getCmd("proxy", "wpscanProxy", sortedWpDirs=sorted_wp_dirs, httpProxy=proxy_ports[0], httpProxyPort=proxy_http_port)
                                                cms_commands.append(wpscan_cmd)
                                                if cms_counter >= 1:
                                                    hasPrinted = True
                                            manual_brute_force_script = f"""
#!/bin/bash

if [[ -n $(grep -i "User(s) Identified" {c.getPath("proxy", "wpscanReport", proxyPort=proxy_http_port)}) ]]; then
    grep -w -A 100 "User(s)" {c.getPath("proxy", "wpscanReport", proxyPort=proxy_http_port)} | grep -w "[+]" | cut -d " " -f 2 | head -n -7 >{c.getPath("proxy", "wpUsers")}
    {c.getCmd("proxy", "proxychainsCewl", proxyPorts=proxy_http_port)}
    sleep 10
    echo "Adding John Rules to Cewl Wordlist!"
    {c.getCmd("proxy", "john")}
    sleep 3
    # brute force again with wpscan
    {c.getCmd("proxy", "wpscanCewlBrute", proxyPorts=proxy_http_port, httpProxy=proxy_ports[0])}
    sleep 1
    if grep -i "No Valid Passwords Found" wordpress-cewl-brute2.txt; then
        if [ -s {c.getPath("proxy", "johnCewl")} ]; then
            {c.getCmd("proxy", "wpscanJohnCewlBrute", proxyPorts=proxy_http_port, httpProxy=proxy_ports[0])}
        else
            echo "John wordlist is empty :("
        fi
        sleep 1
        if grep -i "No Valid Passwords Found" {c.getPath("proxy","wpscanJohnCoolBrute")}; then
            {c.getCmd("proxy", "wpscanFastTrackBrute", proxyPorts=proxy_http_port, httpProxy=proxy_ports[0])}
        fi
    fi
fi
                                            """.rstrip()
                                            try:
                                                with open(c.getPath("proxy", "wordpressBashBruteScript"), "w") as wpb:
                                                    print("Creating wordpress Brute Force Script...")
                                                    wpb.write(manual_brute_force_script)
                                                call(f"""chmod +x {c.getPath("proxy", "wordpressBashBruteScript")}""", shell=True)
                                            except FileNotFoundError as fnf_error:
                                                print(fnf_error)

                                        if "Drupal" in cms:
                                            drupal_cmd = c.getCmd("proxy", "droopescan", proxyPorts=proxy_http_port)
                                            cms_commands.append(drupal_cmd)
                                        if "Joomla" in cms:
                                            joomla_cmd = c.getCmd("proxy", "joomscan", proxyPorts=proxy_http_port, httpProxy=proxy_ports[0])
                                            cms_commands.append(joomla_cmd)
                                        if "Magento" in cms:
                                            magento_cmd = c.getCmd("proxy", "magescan", proxyPorts=proxy_http_port)
                                            cms_commands.append(magento_cmd)
                                        if "WebDAV" in cms or ("Microsoft-IIS 6.0" in cms):
                                            webdav_cmd2 = c.getCmd("proxy", "webdavNmap", proxyPort=proxy_http_port)
                                            cms_commands.append(webdav_cmd2)

            sorted_commands = sorted(set(cms_commands))
            commands_to_run = []
            for i in sorted_commands:
                commands_to_run.append(i)
            mpCmds = tuple(commands_to_run)
            self.cms_processes = mpCmds
