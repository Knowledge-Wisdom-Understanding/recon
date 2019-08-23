#!/usr/bin/env python3

import os
# from multiprocessing import Pool
import time
from sty import fg, bg, ef, rs, RgbFg
from lib import nmapParser


class EnumWeb:
    def __init__(self, target):
        self.target = target
        self.processes = ''

    def Scan(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        http_ports = np.http_ports
        if len(http_ports) == 0:
            pass
        else:
            if not os.path.exists('{}-Report/web'.format(self.target)):
                os.makedirs('{}-Report/web'.format(self.target))

            for port in http_ports:
                commands = (
                    'whatweb -v -a 3 http://{}:{} >{}-Report/web/whatweb-{}-{}.txt'.format(self.target, port, self.target, self.target, port ),
                    'wafw00f http://{}:{} >{}-Report/web/wafw00f-{}-{}.txt'.format(self.target, port, self.target, self.target, port),
                    'curl -sSik http://{}:{}/robots.txt -m 10 -o {}-Report/web/robots-{}-{}.txt &>/dev/null'.format(self.target, port, self.target, self.target, port),
                    'python3 /opt/dirsearch/dirsearch.py -u http://{}:{} -t 50 -e php,asp,aspx,txt,html -x 403,500 -f --plain-text-report {}-Report/web/dirsearch-{}-{}.log'
                    .format(self.target, port, self.target, self.target, port),
                    # 'python3 /opt/dirsearch/dirsearch.py -u http://{}:{} -t 50 -e php,asp,aspx -f -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x 403,500 --plain-text-report web/dirsearch-dlistsmall-{}-{}.log'
                    # .format(self.target, port, self.target, port),
                    'nikto -ask=no -host http://{}:{} >{}-Report/web/niktoscan-{}-{}.txt 2>&1 &'.format(self.target, port, self.target, self.target, port))
            # c = fg.cyan + 'Enumerating HTTP Ports, Running the following commands:' + fg.rs
            # print(c)
            # green_plus = fg.li_green + '+' + fg.rs
            # cmd_info = '[' + green_plus + ']'
            # for command in commands:
                # print(cmd_info, command)
            self.processes = commands
            # print(self.processes)
