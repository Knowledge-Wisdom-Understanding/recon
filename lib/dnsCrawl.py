#!/usr/bin/env python3

import os
from sty import fg, bg, ef, rs
from subprocess import PIPE, Popen, check_output, STDOUT
import wfuzz
from lib import nmapParser
from subprocess import call
from bs4 import BeautifulSoup, Comment
import requests
import re
from python_hosts.hosts import Hosts, HostsEntry
from utils import config_paths


class checkSource:
    def __init__(self, target):
        self.target = target
        self.htb_source_domains = []

    def cmdline(self, command):
        process = Popen(args=command, stdout=PIPE, shell=True)
        return process.communicate()[0]

    def getLinks(self):
        """Grab all links from web server homepage i.e. http://IP:PORT/ and look for .htb domain names.
        If a .htb domain is found, add the hostname to the /etc/hosts file and then proceed to fuzz the domain
        for subdomains using wfuzz. If a valid subdomain is found, add the subdomain to the /etc/hosts file as 
        well using python_hosts library merge_names parameter."""
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        http_ports = np.http_ports
        cmd_info = "[" + fg.li_green + "+" + fg.rs + "]"
        cmd_info_orange = "[" + fg.li_yellow + "+" + fg.rs + "]"
        c = config_paths.Configurator(self.target)
        c.createConfig()
        if len(http_ports) != 0:
            if not os.path.exists(f"""{c.getPath("webDir")}"""):
                os.makedirs(f"""{c.getPath("webDir")}""")
            for hp in http_ports:
                url = f"""http://{self.target}:{hp}"""
                wfuzzReport = f"""{c.getPath("wfuzzReport")}"""
                page = requests.get(url)
                data = page.text
                soup = BeautifulSoup(data, "html.parser")
                links = []
                htb = [".htb"]
                source_domain_name = []
                for link in soup.find_all(text=lambda x: ".htb" in x):
                    matches = re.findall(
                        r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{3}",
                        link,
                    )
                    for x in matches:
                        if any(s in x for s in htb):
                            source_domain_name.append(x)
                # print(source_domain_name)
                if len(source_domain_name) != 0:
                    print(
                        f"""{cmd_info_orange} {fg.li_magenta}Found{fg.rs} {fg.cyan}{source_domain_name}{fg.rs} in {fg.li_red}The Source!{fg.rs} http://{self.target}:{hp}"""
                    )
                    print(
                        f"""{cmd_info} {fg.li_magenta}Adding{fg.rs} {fg.li_cyan} {source_domain_name}{fg.rs} to /etc/hosts file"""
                    )
                    hosts = Hosts(path="/etc/hosts")
                    new_entry = HostsEntry(
                        entry_type="ipv4", address=self.target, names=source_domain_name
                    )
                    hosts.add([new_entry], merge_names=True)
                    hosts.write()
                    for d in source_domain_name:
                        self.htb_source_domains.append(d)
                    try:
                        tk5 = f"""{c.getPath("top5Ksubs")}"""
                        print(
                            f"""{cmd_info} wfuzz -z file,{tk5} -u {source_domain_name[0]} -H 'Host: FUZZ.{source_domain_name[0]}'"""
                        )
                        str_domain = source_domain_name[0]
                        fuzz_domain = f"""FUZZ.{source_domain_name[0]}"""
                        for r in wfuzz.fuzz(
                            url=str_domain,
                            hc=[404],
                            payloads=[("file", dict(fn=tk5))],
                            headers=[("Host", fuzz_domain)],
                            printer=(wfuzzReport, "raw"),
                        ):
                            # print(r)
                            pass
                    except Exception as e:
                        print(e)

                    check_occurances = f"""sed -n -e 's/^.*C=//p' {wfuzzReport} | grep -v "Warning:" | cut -d " " -f 1 | sort | uniq -c"""
                    response_num = [
                        i.strip()
                        for i in self.cmdline(check_occurances)
                        .decode("utf-8")
                        .split("\n")
                    ]
                    res_filt = [i.split() for i in sorted(set(response_num))]
                    filt2arr = [c for c in res_filt if len(c) != 0 and int(c[0]) < 5]
                    status_code = []
                    if len(filt2arr) != 0 and (len(filt2arr) < 5):
                        # print(filt2arr)
                        for htprc in filt2arr:
                            status_code.append(htprc[1])
                    if len(status_code) != 0:
                        for status in status_code:
                            # print(status_code)
                            awk_print = "awk '{print $8}'"
                            get_domain_cmd = f"""sed -n -e 's/^.*C={status_code}//p' {wfuzzReport} | {awk_print}"""
                            get_domains = (
                                check_output(get_domain_cmd, shell=True, stderr=STDOUT)
                                .rstrip()
                                .decode("utf-8")
                                .replace('"', "")
                            )
                            subdomains = []
                            if get_domains is not None:
                                subdomains.append(get_domains)
                                sub_d = "{}.{}".format(
                                    subdomains[0], source_domain_name[0]
                                )

                                print(
                                    f"""{cmd_info_orange} {fg.li_blue}Found Subdomain!{fg.rs} {fg.li_green}{sub_d}{fg.rs}"""
                                )
                                print(
                                    f"""{cmd_info}{fg.li_magenta} Adding{fg.rs} {fg.li_cyan}{sub_d}{fg.rs} to /etc/hosts file"""
                                )
                                hosts = Hosts(path="/etc/hosts")
                                new_entry = HostsEntry(
                                    entry_type="ipv4",
                                    address=self.target,
                                    names=[sub_d],
                                )
                                hosts.add([new_entry], merge_names=True)
                                hosts.write()
                                self.htb_source_domains.append(sub_d)


class sourceCommentChecker:
    """sourceCommentChecker does what you think it does. If you don't think you know what it does, Read the code.
    Line by flippin line."""

    def __init__(self, target):
        self.target = target

    def extract_source_comments(self):
        """Search home page for comments in the HTML source code. If any comments are found, 
        Write them to a file in the report/web directory."""
        url = f"""http://{self.target}"""
        c = config_paths.Configurator(self.target)
        c.createConfig()
        page = requests.get(url)
        data = page.text
        soup = BeautifulSoup(data, "html.parser")
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        comments_arr = [c.extract() for c in comments]
        if len(comments_arr) != 0:
            try:
                with open(f"""{c.getPath("sourceComments")}""", "w") as com:
                    for c in comments_arr:
                        com_str = c.rstrip("\n")
                        com.write(com_str)
            except FileNotFoundError as fnf:
                print(fnf)

