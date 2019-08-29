#!/usr/bin/env python3

import os
from sty import fg, bg, ef, rs, RgbFg
from lib import nmapParser
from lib import dnsenum


class EnumWebSSL:
    def __init__(self, target):
        self.target = target
        self.processes = ""
        self.proxy_processes = ""

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
            b = (
                fg.li_cyan
                + "Enumerating HTTPS/SSL Ports, Running the following commands:"
                + fg.rs
            )
            print(b)
            if len(hostnames) == 0:
                for sslport in ssl_ports:
                    commands = (
                        f"whatweb -v -a 3 https://{self.target}:{sslport} | tee {self.target}-Report/webSSL/whatweb-{self.target}-{sslport}.txt",
                        f"wafw00f https://{self.target}:{sslport} >{self.target}-Report/webSSL/wafw00f-{self.target}-{sslport}.txt",
                        f"curl -sSik https://{self.target}:{sslport}/robots.txt -m 10 -o {self.target}-Report/webSSL/robots-{self.target}-{sslport}.txt &>/dev/null",
                        f"python3 /opt/dirsearch/dirsearch.py -u https://{self.target}:{sslport} -t 30 -e php,asp,aspx,html,txt -x 403,500 -w wordlists/dicc.txt --plain-text-report {self.target}-Report/webSSL/dirsearch-{self.target}-{sslport}.log",
                        f"python3 /opt/dirsearch/dirsearch.py -u https://{self.target}:{sslport} -t 70 -e php -f -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x 403,500 --plain-text-report {self.target}-Report/webSSL/dirsearch-dlistmedium-{self.target}-{sslport}.log",
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
                            f"python3 /opt/dirsearch/dirsearch.py -u https://{i}:{ssl_port2} -t 50 -e php,asp,aspx,txt,html -x 403,500 -f --plain-text-report {self.target}-Report/webSSL/dirsearch-{i}-{ssl_port2}.log",
                            f"python3 /opt/dirsearch/dirsearch.py -u https://{i}:{ssl_port2} -t 50 -e php -f -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x 403,500 --plain-text-report {self.target}-Report/webSSL/dirsearch-dlistsmall-{i}-{ssl_port2}.log",
                            f"nikto -ask=no -host https://{i}:{ssl_port2} -ssl  >{self.target}-Report/webSSL/niktoscan-{i}-{ssl_port2}.txt 2>&1 &",
                        )

            self.processes = commands

    def sslProxyScan(self):
        npp = nmapParser.NmapParserFunk(self.target)
        npp.openProxyPorts()
        proxy_ssl_ports = npp.proxy_ssl_ports
        proxy_ports2 = npp.proxy_ports
        ssl_proxy_cmds = []
        cwd = os.getcwd()
        if len(proxy_ssl_ports) == 0:
            pass
        else:
            if not os.path.exists(f"{self.target}-Report/proxy"):
                os.makedirs(f"{self.target}-Report/proxy")
            if not os.path.exists(f"{self.target}-Report/proxy/webSSL"):
                os.makedirs(f"{self.target}-Report/proxy/webSSL")
            for proxy in proxy_ports2:
                for proxy_ssl_port in proxy_ssl_ports:
                    a = f"{fg.li_cyan} Enumerating HTTPS Ports Through {proxy}, Running the following commands: {fg.rs}"
                    print(a)
                    proxy_https_string_ports = ",".join(map(str, proxy_ssl_ports))
                    proxy_whatwebCMD = f"whatweb -v -a 3 --proxy {self.target}:{proxy} https://127.0.0.1:{proxy_ssl_port} | tee {self.target}-Report/proxy/webSSL/whatweb-proxy-{self.target}-{proxy_ssl_port}.txt"
                    ssl_proxy_cmds.append(proxy_whatwebCMD)
                    proxy_dirsearch_cmd = f"python3 /opt/dirsearch/dirsearch.py -e php,asp,aspx,txt,html -x 403,500 -t 50 -w wordlists/dicc.txt --proxy {self.target}:{proxy} -u https://127.0.0.1:{proxy_http_port} --plain-text-report {self.target}-Report/proxy/webSSL/dirsearch-127.0.0.1-{proxy}-{proxy_http_port}.log"
                    ssl_proxy_cmds.append(proxy_dirsearch_cmd)
                    proxy_dirsearch_cmd2 = f"python3 /opt/dirsearch/dirsearch.py -u https://{self.target}:{port} -t 80 -e php,asp,aspx -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x 403,500 --plain-text-report {self.target}-Report/proxy/webSSL/dirsearch-dlistsmall-{self.target}-{port}.log"
                    ssl_proxy_cmds.append(proxy_dirsearch_cmd2)
                    proxy_nikto_cmd = f"nikto -ask=no -host https://127.0.0.1:{proxy_ssl_port}/ -useproxy https://{self.target}:{proxy}/ > {self.target}-Report/proxy/webSSL/nikto-{self.target}-{proxy_ssl_port}-proxy-scan.txt 2>&1 &"
                    ssl_proxy_cmds.append(proxy_nikto_cmd)

            sorted_commands = sorted(set(ssl_proxy_cmds))
            commands_to_run = []
            for i in sorted_commands:
                commands_to_run.append(i)
            wpSslCmds = tuple(commands_to_run)
            self.proxy_processes = wpSslCmds
            # print(self.processes)

