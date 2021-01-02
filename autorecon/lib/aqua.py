#!/usr/bin/env python3

import os
from sty import fg
from autorecon.lib import nmapParser
from subprocess import call
from shutil import which
from autorecon.utils import config_parser


class Aquatone:
    """The Aquatone Class will attempt to generate a nice aquatone report provided there are found URLSreturned from the Web Server using Dirsearch. If so, This class will then proceed to open up the freshly generated report in firefox provided that firefox is installed on your machine which it is by default in kali linux. :)"""

    def __init__(self, target):
        self.target = target

    def Scan(self):
        """Create Aquatone Report based off of the dirsearch results. If the length of urls.txt is greater than 150, aquatone won't
        be run as this might be an indication of too many false positives.
        """
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        npp = nmapParser.NmapParserFunk(self.target)
        npp.openProxyPorts()
        c = config_parser.CommandParser(f"{os.path.expanduser('~')}/.config/autorecon/config.yaml", self.target)
        cmd_info = "[" + fg.li_green + "+" + fg.rs + "]"
        ssl_ports = np.ssl_ports
        http_ports = np.http_ports
        proxy_http_ports = npp.proxy_http_ports
        proxy_ssl_ports = npp.proxy_ssl_ports
        proxy_ports = np.proxy_ports
        all_web_ports = []
        all_web_proxy_ports = []
        for x in ssl_ports:
            all_web_ports.append(x)
        for x in http_ports:
            all_web_ports.append(x)
        for x in proxy_http_ports:
            all_web_proxy_ports.append(x)
        for x in proxy_ssl_ports:
            all_web_proxy_ports.append(x)
        all_web_ports_comma_list = ",".join(map(str, all_web_ports))
        all_web_proxy_ports_comma_list = ",".join(map(str, all_web_proxy_ports))
        if not os.path.exists(c.getPath("web", "aquatoneDir")):
            os.makedirs(c.getPath("web", "aquatoneDir"))
        aquatone_urls = c.getPath("web", "aquatoneDirUrls")

        def get_num_urls(filepath: str) -> int:
            with open(filepath, 'r') as fp:
                _num_urls = len([l.rstrip() for l in fp.readlines() if l.startswith('http')])
            return _num_urls

        if os.path.exists(aquatone_urls):
            num_urls = get_num_urls(aquatone_urls)
            if num_urls < 150 and (num_urls != 0):
                aquatone_cmd = c.getCmd("web", "aquatone", allWebPorts=all_web_ports_comma_list)
                print(cmd_info, aquatone_cmd)
                call(aquatone_cmd, shell=True)
                if not which("firefox"):
                    pass
                else:
                    if os.path.exists(c.getPath("web", "aquatoneReport")):
                        print(f"""{fg.cyan}Opening Aquatone Report {fg.rs}""")
                        open_in_ff_cmd = f"""firefox {c.getPath("web","aquatoneReport")} &"""
                        call(open_in_ff_cmd, shell=True)
        aquatone_proxy_urls = c.getPath("proxy", "aquatoneDirProxyUrls")
        if os.path.exists(aquatone_proxy_urls):
            num_urls = get_num_urls(aquatone_proxy_urls)
            if num_urls < 150 and (num_urls != 0):
                aquatone_cmd = c.getCmd("proxy", "aquatoneProxy", allWebProxyPorts=all_web_proxy_ports_comma_list, proxyPorts=proxy_ports[0])
                print(cmd_info, aquatone_cmd)
                call(aquatone_cmd, shell=True)
                if not which("firefox"):
                    pass
                else:
                    if os.path.exists(c.getPath("proxy", "aquatoneProxyReport")):
                        open_in_ff_proxy_cmd = f"""firefox {c.getPath("proxy", "aquatoneProxyReport")} &"""
                        call(open_in_ff_proxy_cmd, shell=True)
