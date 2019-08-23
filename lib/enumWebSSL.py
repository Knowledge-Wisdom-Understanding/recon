#!/usr/bin/env python3

import os
# from multiprocessing import Pool
import time
from sty import fg, bg, ef, rs, RgbFg
from lib import nmapParser


class EnumWebSSL:
    def __init__(self, target):
        self.target = target
        self.processes = ''

    def Scan(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        ssl_ports = np.ssl_ports
        if len(ssl_ports) == 0:
            pass
        else:
            if not os.path.exists('{}-Report/web'.format(self.target)):
                os.makedirs('{}-Report/web'.format(self.target))

            for sslport in ssl_ports:
                commands = (
                    'whatweb -v -a 3 https://{}:{} >{}-Report/web/whatweb-{}-{}.txt'.format(
                        self.target, sslport, self.target, self.target,
                        sslport), 'wafw00f https://{}:{} >{}-Report/web/wafw00f-{}-{}.txt'.format(
                            self.target, sslport, self.target, self.target, sslport),
                    'curl -sSik https://{}:{}/robots.txt -m 10 -o {}-Report/web/robots-{}-{}.txt &>/dev/null'.format(self.target, sslport, self.target, self.target, sslport),
                    'python3 /opt/dirsearch/dirsearch.py -u https://{}:{} -t 50 -e php,asp,aspx,txt -x 403,500 -f --plain-text-report {}-Report/web/dirsearch-{}-{}.log'
                    .format(self.target, sslport, self.target, self.target, sslport),
                    # 'python3 /opt/dirsearch/dirsearch.py -u https://{}:{} -t 50 -e php,asp,aspx -f -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x 403,500 --plain-text-resslport web/dirsearch-dlistsmall-{}-{}.log'
                    # .format(self.target, sslport, self.target, self.target, sslport),
                    'nikto -ask=no -host https://{}:{} -ssl  >{}-Report/web/niktoscan-{}-{}.txt 2>&1 &'.format(
                        self.target, sslport, self.target, self.target, sslport))
            # c = fg.cyan + 'Enumerating HTTPS/SSL Ports, Running the following commands:' + fg.rs
            # print(c)
            # green_plus = fg.li_green + '+' + fg.rs
            # cmd_info = '[' + green_plus + ']'
            # for command in commands:
            #     print(cmd_info, command)
            self.processes = commands
            # print(self.processes)