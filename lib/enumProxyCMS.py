#!/usr/bin/env python3

import os
from sty import fg, bg, ef, rs
from lib import nmapParser
from lib import domainFinder
from utils import helper_lists
from subprocess import call
import glob


class EnumProxyCMS:
    def __init__(self, target):
        self.target = target
        self.processes = ""
        self.cms_processes = ""
        self.proxy_processes = ""
        self.redirect_hostname = []

    def proxyCMS(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        npp = nmapParser.NmapParserFunk(self.target)
        npp.openProxyPorts()
        proxy_http_ports = npp.proxy_http_ports
        proxy_ports = np.proxy_ports
        cmd_info = "[" + fg.li_green + "+" + fg.rs + "]"
        green = fg.li_green
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
            for proxy_http_port in proxy_http_ports:
                cwd = os.getcwd()
                reportPath = f"{cwd}/{self.target}-Report/proxy/*"
                reportDir = f"{cwd}/{self.target}-Report"
                whatweb_files = []
                proxy_urls_path = f"{reportDir}/aquatone/proxy-urls.txt"
                wordpress_url = []
                wp = helper_lists.Wordpress(self.target)
                wordpressDirs = wp.wordpress_dirs
                if os.path.exists(proxy_urls_path):
                    try:
                        with open(proxy_urls_path, "r") as purls:
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
                                whatweb_proxy_cmd = f"whatweb -v -a 3 --proxy {self.target}:{proxy_ports[0]} {wpdir} > {reportDir}/proxy/web/whatweb-proxy-{proxy_http_port}-{count}.txt"
                                call(whatweb_proxy_cmd, shell=True)
                                if count >= 2:
                                    break
                            except:
                                pass

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
                                fword = word.replace("[", " ").replace("]", " ").replace(",", " ")
                                for cms in cms_strings:
                                    if cms in fword:
                                        if "WordPress" in cms and not hasPrinted:
                                            print(f"{teal}Found WordPress!{reset}")
                                            cms_counter += 1
                                            if len(sorted_wp_dirs) != 0:
                                                wpscan_cmd = f"wpscan --no-update --url {sorted_wp_dirs[0]} --proxy http://{self.target}:{proxy_ports[0]} --wp-content-dir wp-content --enumerate vp,vt,cb,dbe,u,m --plugins-detection aggressive | tee {reportDir}/proxy/web/wpscan-{proxy_http_port}.log"
                                                cms_commands.append(wpscan_cmd)
                                                if cms_counter >= 1:
                                                    hasPrinted = True
                                            manual_brute_force_script = f"""
#!/bin/bash

if [[ -n $(grep -i "User(s) Identified" {reportDir}/proxy/web/wpscan-{proxy_http_port}.log) ]]; then
    grep -w -A 100 "User(s)" {reportDir}/proxy/web/wpscan-{proxy_http_port}.log | grep -w "[+]" | cut -d " " -f 2 | head -n -7 >{reportDir}/proxy/web/wp-users.txt
    proxychains cewl http://127.0.0.1:{proxy_http_port}/ -m 3 -w {reportDir}/proxy/web/cewl-list.txt
    sleep 10
    echo "Adding John Rules to Cewl Wordlist!"
    john --rules --wordlist={reportDir}/proxy/web/cewl-list.txt --stdout >{reportDir}/proxy/web/john-cool-list.txt
    sleep 3
    # brute force again with wpscan
    wpscan --no-update --url http://127.0.0.1:{proxy_http_port}/ --proxy http://{self.target}:{proxy_ports[0]} --wp-content-dir wp-login.php -U {reportDir}/proxy/web/wp-users.txt -P {reportDir}/proxy/web/cewl-list.txt threads 50 | tee {reportDir}/proxy/web/wordpress-cewl-brute.txt
    sleep 1
    if grep -i "No Valid Passwords Found" wordpress-cewl-brute2.txt; then
        if [ -s {reportDir}/proxy/web/john-cool-list.txt ]; then
            wpscan --no-update --url http://127.0.0.1:{proxy_http_port}/ --proxy http://{self.target}:{proxy_ports[0]} --wp-content-dir wp-login.php -U {reportDir}/proxy/web/wp-users.txt -P {reportDir}/proxy/web/john-cool-list.txt threads 50 | tee {reportDir}/proxy/web/wordpress-john-cewl-brute.txt
        else
            echo "John wordlist is empty :("
        fi
        sleep 1
        if grep -i "No Valid Passwords Found" {reportDir}/proxy/web/wordpress-john-cewl-brute.txt; then
            wpscan --no-update --url http://127.0.0.1:{proxy_http_port}/ --proxy http://{self.target}:{proxy_ports[0]} --wp-content-dir wp-login.php -U {reportDir}/proxy/web/wp-users.txt -P /usr/share/wordlists/fasttrack.txt threads 50 | tee {reportDir}/proxy/web/wordpress-fasttrack-brute.txt
        fi
    fi
fi
                                            """.rstrip()
                                            try:
                                                with open(
                                                    f"{reportDir}/proxy/web/wordpressBrute.sh", "w"
                                                ) as wpb:
                                                    print(
                                                        "Creating wordpress Brute Force Script..."
                                                    )
                                                    wpb.write(manual_brute_force_script)
                                                call(
                                                    f"chmod +x {reportDir}/proxy/web/wordpressBrute.sh",
                                                    shell=True,
                                                )
                                            except FileNotFoundError as fnf_error:
                                                print(fnf_error)

                                        if "Drupal" in cms:
                                            drupal_cmd = f"proxychains droopescan scan drupal -u http://127.0.0.1:{proxy_http_port}/ -t 32 | tee {reportDir}/proxy/web/drupalscan-{self.target}-{proxy_http_port}.log"
                                            cms_commands.append(drupal_cmd)
                                        if "Joomla" in cms:
                                            joomla_cmd = f"joomscan --url http://127.0.0.1:{proxy_http_port}/ -ec --proxy http://{self.target}:{proxy_ports[0]} | tee {reportDir}/proxy/web/joomlascan-{self.target}-{proxy_http_port}.log"
                                            cms_commands.append(joomla_cmd)
                                        if "Magento" in cms:
                                            magento_cmd = f"cd /opt/magescan && proxychains bin/magescan scan:all http://127.0.0.1:{proxy_http_port}/ | tee {reportDir}/proxy/web/magentoscan-{self.target}-{proxy_http_port}.log && cd - &>/dev/null"
                                            cms_commands.append(magento_cmd)
                                        if "WebDAV" in cms:
                                            webdav_cmd = f"proxychains davtest -move -sendbd auto -url http://127.0.0.1:{proxy_http_port}/ | tee {reportDir}/proxy/web/davtestscan-{self.target}-{proxy_http_port}.log"
                                            webdav_cmd2 = f"proxychains nmap -Pn -vv -sT -sV -p {proxy_http_port} --script=http-iis-webdav-vuln.nse -oA {self.target}-Report/nmap/webdav 127.0.0.1"
                                            cms_commands.append(webdav_cmd)
                                            cms_commands.append(webdav_cmd2)

            sorted_commands = sorted(set(cms_commands))
            commands_to_run = []
            for i in sorted_commands:
                commands_to_run.append(i)
            mpCmds = tuple(commands_to_run)
            self.cms_processes = mpCmds
