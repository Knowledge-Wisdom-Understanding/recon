#!/usr/bin/env python3

import os
from sty import fg, bg, ef, rs, RgbFg
from lib import nmapParser
from lib import dnsenum


class EnumWebSSL:
    def __init__(self, target):
        self.target = target
        self.processes = ""

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
                fg.cyan
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
                        f"python3 /opt/dirsearch/dirsearch.py -u https://{self.target}:{sslport} -t 20 -e php,asp,aspx,html,txt -x 403,500 -f --plain-text-report {self.target}-Report/webSSL/dirsearch-{self.target}-{sslport}.log",
                        f"python3 /opt/dirsearch/dirsearch.py -u https://{self.target}:{sslport} -t 80 -e php -f -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x 403,500 --plain-text-report {self.target}-Report/webSSL/dirsearch-dlistmedium-{self.target}-{sslport}.log",
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

