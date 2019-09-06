#!/usr/bin/env python3

import os
from sty import fg, bg, ef, rs
from lib import nmapParser
from lib import dnsenum
import glob


class EnumWebSSL:
    def __init__(self, target):
        self.target = target
        self.processes = ""
        self.proxy_processes = ""
        self.cms_processes = ""

    def Scan(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        df = dnsenum.DnsEnum(self.target)
        df.GetHostNames()
        hostnames = df.hostnames
        ssl_ports = np.ssl_ports

        if len(ssl_ports) == 0:
            pass
        else:
            if not os.path.exists(f"{self.target}-Report/webSSL"):
                os.makedirs(f"{self.target}-Report/webSSL")
            if not os.path.exists(f"{self.target}-Report/aquatone"):
                os.makedirs(f"{self.target}-Report/aquatone")
            b = fg.li_cyan + "Enumerating HTTPS/SSL Ports, Running the following commands:" + fg.rs
            print(b)
            if len(hostnames) == 0:
                commands = ()
                for sslport in ssl_ports:
                    commands = commands + (
                        f"whatweb -v -a 3 https://{self.target}:{sslport} | tee {self.target}-Report/webSSL/whatweb-{self.target}-{sslport}.txt",
                        f"wafw00f https://{self.target}:{sslport} >{self.target}-Report/webSSL/wafw00f-{self.target}-{sslport}.txt",
                        f"curl -sSik https://{self.target}:{sslport}/robots.txt -m 10 -o {self.target}-Report/webSSL/robots-{self.target}-{sslport}.txt &>/dev/null",
                        f"python3 /opt/dirsearch/dirsearch.py -u https://{self.target}:{sslport}/ -t 30 -e php,asp,aspx,html,txt -x 403,500 -w wordlists/dicc.txt --plain-text-report {self.target}-Report/webSSL/dirsearch-{self.target}-{sslport}.log",
                        f"python3 /opt/dirsearch/dirsearch.py -u https://{self.target}:{sslport}/ -t 80 -e php,asp,aspx,html,txt -w /usr/share/wordlists/dirb/big.txt -x 403,500 --plain-text-report {self.target}-Report/webSSL/dirsearch-big-{self.target}-{sslport}.log",
                        f"nikto -ask=no -host https://{self.target}:{sslport} -ssl  >{self.target}-Report/webSSL/niktoscan-{self.target}-{sslport}.txt 2>&1 &",
                    )
            else:
                for ssl_port2 in ssl_ports:
                    commands = ()
                    for i in hostnames:
                        commands = commands + (
                            f"whatweb -v -a 3 https://{i}:{ssl_port2} >{self.target}-Report/webSSL/whatweb-{i}-{ssl_port2}.txt",
                            f"wafw00f https://{i}:{ssl_port2} >{self.target}-Report/webSSL/wafw00f-{i}-{ssl_port2}.txt",
                            f"curl -sSik https://{i}:{ssl_port2}/robots.txt -m 10 -o {self.target}-Report/webSSL/robots-{i}-{ssl_port2}.txt &>/dev/null",
                            f"python3 /opt/dirsearch/dirsearch.py -u https://{i}:{ssl_port2}/ -t 50 -e php,asp,aspx,txt,html -x 403,500 --plain-text-report {self.target}-Report/webSSL/dirsearch-{i}-{ssl_port2}.log",
                            f"python3 /opt/dirsearch/dirsearch.py -u https://{i}:{ssl_port2}/ -t 50 -e php,asp,aspx,txt,html -w /usr/share/wordlists/dirb/big.txt -x 403,500 --plain-text-report {self.target}-Report/webSSL/dirsearch-big-{i}-{ssl_port2}.log",
                            f"nikto -ask=no -host https://{i}:{ssl_port2} -ssl  >{self.target}-Report/webSSL/niktoscan-{i}-{ssl_port2}.txt 2>&1 &",
                        )

            self.processes = commands

    def ScanWebOption(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        df = dnsenum.DnsEnum(self.target)
        df.GetHostNames()
        hostnames = df.hostnames
        ssl_ports = np.ssl_ports

        if len(ssl_ports) == 0:
            pass
        else:
            if not os.path.exists(f"{self.target}-Report/webSSL"):
                os.makedirs(f"{self.target}-Report/webSSL")
            if not os.path.exists(f"{self.target}-Report/aquatone"):
                os.makedirs(f"{self.target}-Report/aquatone")
            b = fg.li_cyan + "Enumerating HTTPS/SSL Ports, Running the following commands:" + fg.rs
            print(b)
            if len(hostnames) == 0:
                for sslport in ssl_ports:
                    commands = (
                        f"whatweb -v -a 3 https://{self.target}:{sslport} | tee {self.target}-Report/webSSL/whatweb-{self.target}-{sslport}.txt",
                        f"wafw00f https://{self.target}:{sslport} >{self.target}-Report/webSSL/wafw00f-{self.target}-{sslport}.txt",
                        f"curl -sSik https://{self.target}:{sslport}/robots.txt -m 10 -o {self.target}-Report/webSSL/robots-{self.target}-{sslport}.txt &>/dev/null",
                        f"python3 /opt/dirsearch/dirsearch.py -u https://{self.target}:{sslport} -t 80 -e php,asp,aspx,html -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x 403,500 --plain-text-report {self.target}-Report/webSSL/dirsearch-dlistmedium-{self.target}-{sslport}.log",
                        f"python3 /opt/dirsearch/dirsearch.py -u https://{self.target}:{sslport} -t 50 -e php,asp,aspx,html,txt,git,bak,tar,gz,7z,json,zip,rar,bz2,pdf,md,pl,cgi -x 403,500 -w /usr/share/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt --plain-text-report {self.target}-Report/webSSL/dirsearch-raftfiles-{self.target}-{sslport}.log",
                        f"python3 /opt/dirsearch/dirsearch.py -u https://{self.target}:{sslport} -t 50 -e php,asp,aspx,html,txt -x 403,500 -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt --plain-text-report {self.target}-Report/webSSL/dirsearch-raftdirs-{self.target}-{sslport}.log",
                        f"python3 /opt/dirsearch/dirsearch.py -u https://{self.target}:{sslport} -t 50 -e php,asp,aspx,txt,html -w wordlists/foreign.txt -x 403,500 --plain-text-report {self.target}-Report/webSSL/dirsearch-foreign-{self.target}-{sslport}.log",
                        f"nikto -ask=no -host https://{self.target}:{sslport} -ssl  >{self.target}-Report/webSSL/niktoscan-{self.target}-{sslport}.txt 2>&1 &",
                    )
            else:
                for ssl_port2 in ssl_ports:
                    commands = ()
                    for i in hostnames:
                        commands = commands + (
                            f"whatweb -v -a 3 https://{i}:{ssl_port2} >{self.target}-Report/webSSL/whatweb-{i}-{ssl_port2}.txt",
                            f"wafw00f https://{i}:{ssl_port2} >{self.target}-Report/webSSL/wafw00f-{i}-{ssl_port2}.txt",
                            f"curl -sSik https://{i}:{ssl_port2}/robots.txt -m 10 -o {self.target}-Report/webSSL/robots-{i}-{ssl_port2}.txt &>/dev/null",
                            f"python3 /opt/dirsearch/dirsearch.py -u https://{i}:{ssl_port2} -t 50 -e php,asp,aspx,html,txt,git,bak,tar,gz,7z,json,zip,rar,bz2,pdf,md,pl,cgi -x 403,500 -w /usr/share/seclists/Discovery/Web-Content/raft-large-files-lowercase.txt --plain-text-report {self.target}-Report/webSSL/dirsearch-raftfiles-{i}-{ssl_port2}.log",
                            f"python3 /opt/dirsearch/dirsearch.py -u https://{i}:{ssl_port2} -t 50 -e php,asp,aspx,html,txt -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x 403,500 --plain-text-report {self.target}-Report/webSSL/dirsearch-dlistmedium-{i}-{ssl_port2}.log",
                            f"python3 /opt/dirsearch/dirsearch.py -u https://{i}:{ssl_port2} -t 50 -e php,asp,aspx,txt,html -w wordlists/foreign.txt -x 403,500 --plain-text-report {self.target}-Report/webSSL/dirsearch-foreign-{i}-{ssl_port2}.log",
                            f"python3 /opt/dirsearch/dirsearch.py -u https://{i}:{ssl_port2} -t 50 -e php,asp,aspx,html,txt -x 403,500 -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt --plain-text-report {self.target}-Report/webSSL/dirsearch-raftlargedirs-{i}-{ssl_port2}.log",
                            f"nikto -ask=no -host https://{i}:{ssl_port2} -ssl  >{self.target}-Report/webSSL/niktoscan-{i}-{ssl_port2}.txt 2>&1 &",
                        )

            self.processes = commands

    def sslProxyScan(self):
        npp = nmapParser.NmapParserFunk(self.target)
        npp.openProxyPorts()
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        proxy_ssl_ports = npp.proxy_ssl_ports
        proxy_ports = np.proxy_ports
        # cwd = os.getcwd()
        if len(proxy_ssl_ports) == 0:
            pass
        else:
            if not os.path.exists(f"{self.target}-Report/proxy"):
                os.makedirs(f"{self.target}-Report/proxy")
            if not os.path.exists(f"{self.target}-Report/proxy/webSSL"):
                os.makedirs(f"{self.target}-Report/proxy/webSSL")
            proxy_commands = ()
            for proxy in proxy_ports:
                print(
                    f"{fg.li_cyan} Enumerating HTTPS Ports Through {proxy}, Running the following commands: {fg.rs}"
                )
                for proxy_ssl_port in proxy_ssl_ports:
                    proxy_commands = proxy_commands + (
                        f"whatweb -v -a 3 --proxy {self.target}:{proxy} https://127.0.0.1:{proxy_ssl_port} | tee {self.target}-Report/proxy/webSSL/whatweb-proxy-{self.target}-{proxy_ssl_port}.txt",
                        f"python3 /opt/dirsearch/dirsearch.py -e php,asp,aspx,txt,html -x 403,500 -t 50 -w wordlists/dicc.txt --proxy {self.target}:{proxy} -u https://127.0.0.1:{proxy_http_port} --plain-text-report {self.target}-Report/proxy/webSSL/dirsearch-127.0.0.1-{proxy}-{proxy_http_port}.log",
                        f"python3 /opt/dirsearch/dirsearch.py -e php,asp,aspx,txt,html -x 403,500 -t 50 -w /usr/share/wordlists/dirb/big.txt --proxy {self.target}:{proxy} -u https://127.0.0.1:{proxy_http_port} --plain-text-report {self.target}-Report/proxy/webSSL/dirsearch-127.0.0.1-big-{proxy}-{proxy_http_port}.log",
                        f"nikto -ask=no -host https://127.0.0.1:{proxy_ssl_port}/ -ssl -useproxy https://{self.target}:{proxy}/ > {self.target}-Report/proxy/webSSL/nikto-{self.target}-{proxy_ssl_port}-proxy-scan.txt 2>&1 &",
                    )

            self.proxy_processes = proxy_commands
            # print(self.processes)

    def sslEnumCMS(self):
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
            for ssl_port in ssl_ports:
                cwd = os.getcwd()
                reportPath = f"{cwd}/{self.target}-Report/webSSL/*"
                reportDir = f"{cwd}/{self.target}-Report"
                whatweb_files = []
                whatweb_hostnames = []
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
                                fword = word.replace("[", " ").replace("]", " ").replace(",", " ")
                                for cms in cms_strings:
                                    if cms in fword:
                                        if len(whatweb_hostnames) == 0:
                                            if "WordPress" in cms:
                                                wpscan_cmd = f"wpscan --no-update --disable-tls-checks --url https://{self.target}:{ssl_port}/ --wp-content-dir wp-content --enumerate vp,vt,cb,dbe,u,m --plugins-detection aggressive | tee {reportDir}/webSSL/wpscan-{ssl_port}.log"
                                                cms_commands.append(wpscan_cmd)
                                                manual_brute_force_script = f"""
#!/bin/bash

if [[ -n $(grep -i "User(s) Identified" {reportDir}/webSSL/wpscan-{ssl_port}.log) ]]; then
    grep -w -A 100 "User(s)" {reportDir}/webSSL/wpscan-{ssl_port}.log | grep -w "[+]" | cut -d " " -f 2 | head -n -7 >{reportDir}/webSSL/wp-users.txt
    cewl https://{self.target}:{ssl_port}/ -m 3 -w {reportDir}/webSSL/cewl-list.txt
    sleep 10
    echo "Adding John Rules to Cewl Wordlist!"
    john --rules --wordlist={reportDir}/webSSL/cewl-list.txt --stdout >{reportDir}/webSSL/john-cool-list.txt
    sleep 3
    # brute force again with wpscan
    wpscan --no-update --disable-tls-checks --url https://{self.target}:{ssl_port}/ --wp-content-dir wp-login.php -U {reportDir}/webSSL/wp-users.txt -P {reportDir}/webSSL/cewl-list.txt threads 50 | tee {reportDir}/webSSL/wordpress-cewl-brute.txt
    sleep 1
    if grep -i "No Valid Passwords Found" {reportDir}/webSSL/wordpress-cewl-brute.txt; then
        if [ -s {reportDir}/webSSL/john-cool-list.txt ]; then
            wpscan --no-update --disable-tls-checks --url https://{self.target}:{ssl_port}/ --wp-content-dir wp-login.php -U {reportDir}/webSSL/wp-users.txt -P {reportDir}/webSSL/john-cool-list.txt threads 50 | tee {reportDir}/webSSL/wordpress-john-cewl-brute.txt
        else
            echo "John wordlist is empty :("
        fi
        sleep 1
        if grep -i "No Valid Passwords Found" {reportDir}/webSSL/wordpress-john-cewl-brute.txt; then
            wpscan --no-update --disable-tls-checks --url https://{self.target}:{ssl_port}/ --wp-content-dir wp-login.php -U {reportDir}/webSSL/wp-users.txt -P /usr/share/wordlists/fasttrack.txt threads 50 | tee {reportDir}/webSSL/wordpress-fasttrack-brute.txt
        fi
    fi
fi
                                            """.rstrip()
                                            try:
                                                with open(
                                                    f"{reportDir}/webSSL/wordpressBrute.sh", "w"
                                                ) as wpb:
                                                    print(
                                                        "Creating wordpress Brute Force Script..."
                                                    )
                                                    wpb.write(manual_brute_force_script)
                                                call(
                                                    f"chmod +x {reportDir}/webSSL/wordpressBrute.sh",
                                                    shell=True,
                                                )
                                            except FileNotFoundError as fnf_error:
                                                print(fnf_error)
                                                continue
                                            if "Drupal" in cms:
                                                drupal_cmd = f"droopescan scan drupal -u https://{self.target}:{ssl_port}/ -t 32 | tee {reportDir}/webSSL/drupalscan-{self.target}-{ssl_port}.log"
                                                cms_commands.append(drupal_cmd)
                                            if "Joomla" in cms:
                                                joomla_cmd = f"joomscan --url https://{self.target}:{ssl_port}/ -ec | tee {reportDir}/webSSL/joomlascan-{self.target}-{ssl_port}.log"
                                                cms_commands.append(joomla_cmd)
                                            if "Magento" in cms:
                                                magento_cmd = f"cd /opt/magescan && bin/magescan scan:all -n --insecure https://{self.target}:{ssl_port}/ | tee {reportDir}/webSSL/magentoscan-{self.target}-{ssl_port}.log && cd - &>/dev/null"
                                                cms_commands.append(magento_cmd)
                                            if "WebDAV" in cms:
                                                webdav_cmd = f"davtest -move -sendbd auto -url https://{self.target}:{ssl_port}/ | tee {reportDir}/webSSL/davtestscan-{self.target}-{ssl_port}.log"
                                                webdav_cmd2 = f"nmap -Pn -v -sV -p {ssl_port} --script=http-iis-webdav-vuln.nse -oA {self.target}-Report/nmap/webdav {self.target}"
                                                cms_commands.append(webdav_cmd)
                                                cms_commands.append(webdav_cmd2)
                                        else:
                                            for hn in hostnames:
                                                for whatweb_hn in whatweb_hostnames:
                                                    if hn in whatweb_hn:
                                                        if "WordPress" in cms:
                                                            wpscan_cmd = f"wpscan --no-update --disable-tls-checks --url https://{hn}:{ssl_port}/ --wp-content-dir wp-content --enumerate vp,vt,cb,dbe,u,m --plugins-detection aggressive | tee {reportDir}/webSSL/wpscan-{hn}-{ssl_port}.log"
                                                            cms_commands.append(wpscan_cmd)
                                                        if "Drupal" in cms:
                                                            drupal_cmd = f"droopescan scan drupal -u https://{hn}:{ssl_port}/ -t 32 | tee {reportDir}/webSSL/drupalscan-{hn}-{ssl_port}.log"
                                                            cms_commands.append(drupal_cmd)
                                                        if "Joomla" in cms:
                                                            joomla_cmd = f"joomscan --url https://{hn}:{ssl_port}/ -ec | tee {reportDir}/webSSL/joomlascan-{hn}-{ssl_port}.log"
                                                            cms_commands.append(joomla_cmd)
                                                        if "Magento" in cms:
                                                            magento_cmd = f"cd /opt/magescan && bin/magescan scan:all https://{hn}:{ssl_port}/ | tee {reportDir}/webSSL/magentoscan-{hn}-{ssl_port}.log && cd - &>/dev/null"
                                                            cms_commands.append(magento_cmd)
                                                        if "WebDAV" in cms:
                                                            webdav_cmd = f"davtest -move -sendbd auto -url https://{hn}:{ssl_port}/ | tee {reportDir}/webSSL/davtestscan-{hn}-{ssl_port}.log"
                                                            webdav_cmd2 = f"nmap -Pn -v -sV -p {ssl_port} --script=http-iis-webdav-vuln.nse -oA {reportDir}/nmap/webdav {self.target}"
                                                            cms_commands.append(webdav_cmd)
                                                            cms_commands.append(webdav_cmd2)

            sorted_commands = sorted(set(cms_commands))
            commands_to_run = []
            for i in sorted_commands:
                commands_to_run.append(i)
            mpCmds = tuple(commands_to_run)
            self.cms_processes = mpCmds
