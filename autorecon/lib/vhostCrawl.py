#!/usr/bin/env python3

import os
from sty import fg
from subprocess import PIPE, Popen, check_output, STDOUT
from autorecon.lib import nmapParser
from bs4 import BeautifulSoup, Comment
import re
from python_hosts.hosts import Hosts, HostsEntry
from autorecon.utils import config_parser
import requests
from urllib3.exceptions import InsecureRequestWarning
import warnings
import contextlib


class checkSource:
    def __init__(self, target, hostnames=None):
        """
        param hostnames (list): list of hostnames
        """
        self.target = target
        self.htb_source_domains = []
        self.hostnames = hostnames

    def getLinks(self):
        """Grab all links from web server homepage i.e. http://IP:PORT/ and look for .htb domain names.
        If a .htb domain is found, add the hostname to the /etc/hosts file and then proceed to fuzz the hostname
        for virtual hostname routing using wfuzz. If a valid sub-hostname is found, add the domain to the /etc/hosts file as
        well using python_hosts library merge_names parameter.(Thanks for adding this feature! @jonhadfield)"""

        def cmdline(command):
            process = Popen(args=command, stdout=PIPE, shell=True)
            return process.communicate()[0]

        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        http_ports = np.http_ports
        cmd_info = "[" + fg.li_green + "+" + fg.rs + "]"
        cmd_info_orange = "[" + fg.li_yellow + "+" + fg.rs + "]"
        c = config_parser.CommandParser(f"{os.path.expanduser('~')}/.config/autorecon/config.yaml", self.target)
        if len(http_ports) != 0:
            if not os.path.exists(c.getPath("web", "webDir")):
                os.makedirs(c.getPath("web", "webDir"))
            for hp in http_ports:
                try:
                    url = f"""http://{self.target}:{hp}"""
                    wfuzzReport = c.getPath("web", "wfuzzReport", port=hp)
                    page = requests.get(url, verify=False, timeout=(5, 30))
                    data = page.text
                    soup = BeautifulSoup(data, "html.parser")
                    # links = []
                    htb = [".htb"]
                    source_domain_name = []
                    for link in soup.find_all(text=lambda x: ".htb" in x):
                        matches = re.findall(r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{3}", link)
                        for x in matches:
                            if any(s in x for s in htb):
                                source_domain_name.append(x)
                    for link in soup.find_all('img'):
                        src_matches = link.get('src')
                        matches = re.findall(r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{3}", src_matches)
                        for x in matches:
                            if any(s in x for s in htb):
                                source_domain_name.append(x)
                except requests.exceptions.ConnectionError as ce_error:
                    print("Connection Error: ", ce_error)
                    continue
                except requests.exceptions.Timeout as t_error:
                    print("Connection Timeout Error: ", t_error)
                    continue
                except requests.exceptions.RequestException as req_err:
                    print("Some Ambiguous Exception:", req_err)
                    continue
                if source_domain_name and self.hostnames:
                    all_hostnames = list(set(source_domain_name).union(set(self.hostnames)))
                if source_domain_name and not self.hostnames:
                    all_hostnames = source_domain_name
                if self.hostnames and not source_domain_name:
                    all_hostnames = self.hostnames
                if all_hostnames:
                    vhostnames = [i.lower() for i in sorted(set(all_hostnames))]
                    vhost_log = open(c.getPath("web", "vhostnames"), "a+")
                    for vh in vhostnames:
                        vhost_log.write(vh)
                    vhost_log.close()
                    print(f"""{cmd_info_orange} {fg.li_magenta}Found{fg.rs} {fg.cyan}{vhostnames}{fg.rs} in {fg.li_red}The Source!{fg.rs} http://{self.target}:{hp}""")
                    print(f"""{cmd_info} {fg.li_magenta}Adding{fg.rs} {fg.li_cyan} {vhostnames}{fg.rs} to /etc/hosts file""")
                    hosts = Hosts(path="/etc/hosts")
                    new_entry = HostsEntry(entry_type="ipv4", address=self.target, names=vhostnames)
                    hosts.add([new_entry], merge_names=True)
                    hosts.write()
                    base_domain_name = []
                    for d in vhostnames:
                        self.htb_source_domains.append(d)
                        if d.count('.') == 1:
                            base_domain_name.append(d)
                    try:
                        import wfuzz
                        from tqdm import tqdm

                        tk5 = c.getPath("wordlists", "top5Ksubs")
                        print(f"""{cmd_info} wfuzz -z file,{tk5} -u {base_domain_name[0]}:{hp} -H 'Host: FUZZ.{base_domain_name[0]}:{hp}'""")
                        print(f"{fg.li_yellow}Wfuzz's STDOUT is Hidden to prevent filling up Terminal. Desired Response Codes are unpredictable during initial fuzz session. {fg.rs} STDOUT will be written to {fg.li_magenta}{wfuzzReport}{fg.rs}")
                        str_domain = f"""{base_domain_name[0]}:{hp}"""
                        fuzz_domain = f"""FUZZ.{base_domain_name[0]}:{hp}"""
                        wordlist_lines = 4997
                        with tqdm(total=wordlist_lines) as pbar:
                            for r in wfuzz.fuzz(
                                url=str_domain,
                                hc=[404, 400],
                                payloads=[("file", dict(fn=tk5))],
                                headers=[("Host", fuzz_domain)],
                                printer=(wfuzzReport, "raw"),
                            ):
                                # print(r)
                                pbar.update()
                                pbar.set_description_str(desc=f"{fg.li_yellow}wfuzz{fg.rs}")
                                # pass

                    except Exception as e:
                        print(e)
                    if os.path.exists(wfuzzReport):
                        awk_print = "awk '{print $6}'"
                        check_occurances = f"""sed -n -e 's/^.*C=//p' {wfuzzReport} | grep -v "Warning:" | {awk_print} | sort | uniq -c"""
                        response_num = [
                            i.strip()
                            for i in cmdline(check_occurances)
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
                        if len(status_code) != 0 and len(status_code) <= 5:
                            for _ in status_code:
                                # print(status_code)
                                awk_print = "awk '{print $9}'"
                                get_domain_cmd = f"""grep '{_} Ch' {wfuzzReport} | {awk_print}"""
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
                                        subdomains[0], base_domain_name[0]
                                    )

                                    print(f"""{cmd_info_orange}{fg.li_blue} Found Subdomain!{fg.rs} {fg.li_green}{sub_d}{fg.rs}""")
                                    print(f"""{cmd_info}{fg.li_magenta} Adding{fg.rs} {fg.li_cyan}{sub_d}{fg.rs} to /etc/hosts file""")
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
    """sourceCommentChecker does what you think it does. If you don't think you know what it does, Read the code. Line by flippin line."""

    def __init__(self, target):
        self.target = target

    @contextlib.contextmanager
    def no_ssl_verification(self):
        old_merge_environment_settings = requests.Session.merge_environment_settings
        opened_adapters = set()

        def merge_environment_settings(self, url, proxies, stream, verify, cert):
            # Verification happens only once per connection so we need to close
            # all the opened adapters once we're done. Otherwise, the effects of
            # verify=False persist beyond the end of this context manager.
            opened_adapters.add(self.get_adapter(url))

            settings = old_merge_environment_settings(self, url, proxies, stream, verify, cert)
            settings['verify'] = False

            return settings

        requests.Session.merge_environment_settings = merge_environment_settings

        try:
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', InsecureRequestWarning)
                yield
        finally:
            requests.Session.merge_environment_settings = old_merge_environment_settings

            for adapter in opened_adapters:
                try:
                    adapter.close()
                except:
                    pass

    def extract_source_comments(self):
        """Search home page for comments in the HTML source code. If any comments are found, Write them to a file in the report/web directory."""

        cmd_info = "[" + fg.li_magenta + "*" + fg.rs + "]"
        cmd_info_orange = "[" + fg.li_green + "!" + fg.rs + "]"
        c = config_parser.CommandParser(f"{os.path.expanduser('~')}/.config/autorecon/config.yaml", self.target)
        if os.path.exists(c.getPath("web", "aquatoneDirUrls")):
            url_list = []
            try:
                with open(f"""{c.getPath("web", "aquatoneDirUrls")}""", "r") as urls:
                    for line in urls:
                        _url = line.rstrip()
                        url_list.append(_url)
            except FileNotFoundError as fnf_error:
                print(fnf_error)
                pass
            print(f"{cmd_info}{fg.li_yellow} Checking for comments in the source from found URL's...{fg.rs}")
            url_list = sorted(set(url_list))
            for link in url_list:
                if "https://" in link:
                    if not os.path.exists(c.getPath("webSSL", "webSSLDir")):
                        os.makedirs(c.getPath("webSSL", "webSSLDir"))
                    with self.no_ssl_verification():
                        try:
                            page = requests.get(link)
                            data = page.text
                            soup = BeautifulSoup(data, "html.parser")
                            comments = soup.find_all(string=lambda text: isinstance(text, Comment))
                            comments_arr = [c.extract() for c in comments]
                            if len(comments_arr) != 0:
                                print(f"    {cmd_info_orange}{fg.li_red} Found Comments in the Source!{fg.rs} URL: {fg.li_blue}{link}{fg.rs}")
                                try:
                                    with open(c.getPath("webSSL", "sourceComments"), "a+") as com:
                                        com.write(f"[+] URL: {link}\n")
                                        for cm in comments_arr:
                                            com_str = cm.rstrip("\n")
                                            com.write(f"{com_str}\n")
                                except FileNotFoundError as fnf:
                                    print(fnf)
                        except requests.exceptions.ConnectionError as ce_error:
                            print("Connection Error: ", ce_error)
                            break
                        except requests.exceptions.Timeout as t_error:
                            print("Connection Timeout Error: ", t_error)
                            break
                        except requests.exceptions.RequestException as req_err:
                            print("Some Ambiguous Exception:", req_err)
                            break

                else:
                    if "http://" in link:
                        if not os.path.exists(c.getPath("web", "webDir")):
                            os.makedirs(c.getPath("web", "webDir"))
                        try:
                            page = requests.get(link)
                            data = page.text
                            soup = BeautifulSoup(data, "html.parser")
                            comments = soup.find_all(string=lambda text: isinstance(text, Comment))
                            comments_arr = [c.extract() for c in comments]
                            if len(comments_arr) != 0:
                                print(f"    {cmd_info_orange}{fg.li_red} Found Comments in the Source!{fg.rs} URL: {fg.li_blue}{link}{fg.rs}")
                                try:
                                    with open(c.getPath("web", "sourceComments"), "a+") as com:
                                        com.write(f"[+] URL: {link}\n")
                                        for cm in comments_arr:
                                            com_str = cm.rstrip("\n")
                                            com.write(f"{com_str}\n")
                                except FileNotFoundError as fnf:
                                    print(fnf)
                        except requests.exceptions.ConnectionError as ce_error:
                            print("Connection Error: ", ce_error)
                            break
                        except requests.exceptions.Timeout as t_error:
                            print("Connection Timeout Error: ", t_error)
                            break
                        except requests.exceptions.RequestException as req_err:
                            print("Some Ambiguous Exception:", req_err)
                            break

            if os.path.exists(f"""{c.getPath("web", "sourceComments")}"""):
                print(f"""{cmd_info} Writing Comments to {c.getPath("web","sourceComments")}""")
            if os.path.exists(f"""{c.getPath("webSSL", "sourceComments")}"""):
                print(f"""{cmd_info} Writing Comments to {c.getPath("webSSL","sourceComments")}""")
