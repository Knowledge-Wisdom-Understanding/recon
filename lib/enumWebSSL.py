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
            if not os.path.exists("{}-Report/webSSL".format(self.target)):
                os.makedirs("{}-Report/webSSL".format(self.target))
            b = (
                fg.cyan
                + "Enumerating HTTPS/SSL Ports, Running the following commands:"
                + fg.rs
            )
            print(b)
            if len(hostnames) == 0:
                for sslport in ssl_ports:
                    commands = (
                        "whatweb -v -a 3 https://{}:{} >{}-Report/webSSL/whatweb-{}-{}.txt".format(
                            self.target, sslport, self.target, self.target, sslport
                        ),
                        "wafw00f https://{}:{} >{}-Report/webSSL/wafw00f-{}-{}.txt".format(
                            self.target, sslport, self.target, self.target, sslport
                        ),
                        "curl -sSik https://{}:{}/robots.txt -m 10 -o {}-Report/webSSL/robots-{}-{}.txt &>/dev/null".format(
                            self.target, sslport, self.target, self.target, sslport
                        ),
                        "python3 /opt/dirsearch/dirsearch.py -u https://{}:{} -t 50 -e php,asp,aspx,txt -x 403,500 -f --plain-text-report {}-Report/webSSL/dirsearch-{}-{}.log".format(
                            self.target, sslport, self.target, self.target, sslport
                        ),
                        # 'python3 /opt/dirsearch/dirsearch.py -u https://{}:{} -t 50 -e php,asp,aspx -f -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x 403,500 --plain-text-resslport web/dirsearch-dlistsmall-{}-{}.log'
                        # .format(self.target, sslport, self.target, self.target, sslport),
                        "nikto -ask=no -host https://{}:{} -ssl  >{}-Report/webSSL/niktoscan-{}-{}.txt 2>&1 &".format(
                            self.target, sslport, self.target, self.target, sslport
                        ),
                    )
            else:
                for ssl_port2 in ssl_ports:
                    commands = ()
                    for i in hostnames:
                        commands = commands + (
                            "whatweb -v -a 3 https://{}:{} >{}-Report/webSSL/whatweb-{}-{}.txt".format(
                                i, ssl_port2, self.target, i, ssl_port2
                            ),
                            "wafw00f https://{}:{} >{}-Report/webSSL/wafw00f-{}-{}.txt".format(
                                i, ssl_port2, self.target, i, ssl_port2
                            ),
                            "curl -sSik https://{}:{}/robots.txt -m 10 -o {}-Report/webSSL/robots-{}-{}.txt &>/dev/null".format(
                                i, ssl_port2, self.target, i, ssl_port2
                            ),
                            "python3 /opt/dirsearch/dirsearch.py -u https://{}:{} -t 50 -e php,asp,aspx,txt -x 403,500 -f --plain-text-report {}-Report/webSSL/dirsearch-{}-{}.log".format(
                                i, ssl_port2, self.target, i, ssl_port2
                            ),
                            # 'python3 /opt/dirsearch/dirsearch.py -u https://{}:{} -t 50 -e php,asp,aspx -f -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x 403,500 --plain-text-resslport web/dirsearch-dlistsmall-{}-{}.log'
                            # .format(self.target, ssl_port2, self.target, self.target, ssl_port2),
                            "nikto -ask=no -host https://{}:{} -ssl  >{}-Report/webSSL/niktoscan-{}-{}.txt 2>&1 &".format(
                                i, ssl_port2, self.target, i, ssl_port2
                            ),
                        )

            self.processes = commands

