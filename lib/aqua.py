#!/usr/bin/env python3

import os
from sty import fg, bg, ef, rs
from lib import nmapParser
from subprocess import call, check_output, STDOUT
from shutil import which
from utils import config_parser


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
        c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
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
        if os.path.exists(c.getPath("web", "aquatoneDirUrls")):
            check_lines = f"""wc -l {c.getPath("web","aquatoneDirUrls")} | cut -d ' ' -f 1"""
            num_urls = check_output(check_lines, stderr=STDOUT, shell=True).rstrip()
            # ToDo: open urls.txt and sort urls by occurance of response codes.
            if int(num_urls) < 150:
                aquatone_cmd = c.webCmd("aquatone", allWebPorts=all_web_ports_comma_list)
                print(cmd_info, aquatone_cmd)
                call(aquatone_cmd, shell=True)
                if not which("firefox"):
                    pass
                else:
                    if os.path.exists(c.getPath("web", "aquatoneReport")):
                        print(f"""{fg.cyan}Opening Aquatone Report {fg.rs}""")
                        open_in_ff_cmd = f"""firefox {c.getPath("web","aquatoneReport")} &"""
                        call(open_in_ff_cmd, shell=True)
        if os.path.exists(c.getPath("proxy", "aquatoneDirProxyUrls")):
            check_lines = f"""wc -l {c.getPath("proxy","aquatoneDirProxyUrls")} | cut -d ' ' -f 1"""
            num_urls = check_output(check_lines, stderr=STDOUT, shell=True).rstrip()
            if int(num_urls) < 150:
                aquatone_cmd = c.getCmd("proxy", "aquatoneProxy", allWebProxyPorts=all_web_proxy_ports_comma_list, proxyPorts=proxy_ports[0])
                print(cmd_info, aquatone_cmd)
                call(aquatone_cmd, shell=True)
                if not which("firefox"):
                    pass
                else:
                    if os.path.exists(c.getPath("proxy", "aquatoneProxyReport")):
                        open_in_ff_proxy_cmd = f"""firefox {c.getPath("proxy", "aquatoneProxyReport")} &"""
                        call(open_in_ff_proxy_cmd, shell=True)
