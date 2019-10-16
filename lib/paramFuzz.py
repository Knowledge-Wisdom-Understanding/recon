#!/usr/bin/env python3

import os
from subprocess import call, check_output, STDOUT
from utils import config_parser
from utils import helper_lists
from urllib.parse import urlsplit
from sty import fg
import requests
from urllib3.exceptions import InsecureRequestWarning
import warnings
import contextlib
import logging


class ParamFuzzer:
    """This Class, Param Fuzzer will parse all found urls from dirsearch's output
    to only include urls ending in .php. Next, ParamFuzzer will call parameth and
    begin fuzzing for valid .php?parameters and log output to a file."""

    def __init__(self, target):
        self.target = target
        self.processes = []

    def loginator(self, executed_command):
        c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
        logging.basicConfig(
            filename=c.getPath("report", "commandLog"),
            format='%(asctime)s %(message)s',
            datefmt='%m/%d/%Y %I:%M:%S %p',
            level=logging.INFO
        )
        logging.info(f"[+] {executed_command} \n")

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

    def fuzzMaster(self):
        """fuzzMaster will run parameth to fuzz for valid .php parameters. Will add more extensions soon."""
        c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
        hl = helper_lists.ignoreURLS()
        ignore_urls = hl.ignore_urls
        php_urls = []
        fuzz_cmds = []
        # url_paths = []
        cookie_dict = {}
        if os.path.exists(c.getPath("web", "aquatoneDirUrls")):
            if not os.path.exists(c.getPath("web", "webDir")):
                os.makedirs(c.getPath("web", "webDir"))
            check_lines = f"""wc -l {c.getPath("web","aquatoneDirUrls")} | cut -d ' ' -f 1"""
            num_urls = check_output(check_lines, stderr=STDOUT, shell=True).rstrip()
            if int(num_urls) < 150 and (int(num_urls) != 0):
                try:
                    with open(c.getPath("web", "aquatoneDirUrls"), "r") as found_urls:
                        for line in found_urls:
                            url = line.rstrip()
                            if (
                                url.endswith(".php")
                                and (url not in ignore_urls)
                            ):
                                php_urls.append(url)
                                # url_paths.append(urlsplit(url).path)
                except FileNotFoundError as fnf_error:
                    print(fnf_error)
                    exit()

                if len(php_urls) != 0 and (len(php_urls) < 20):
                    sorted_urls = [u for u in sorted(set(str(x).lower() for x in php_urls))]
                    for url in sorted_urls:
                        with self.no_ssl_verification():
                            try:
                                session = requests.Session()
                                res = session.get(url)
                                cookie_dict.update(session.cookies.get_dict())
                                output_name = urlsplit(url).path
                                upath = str(output_name).replace("/", "-")
                                if not cookie_dict:
                                    fuzz_cmds.append(c.getCmd("web", "parameth", url=url, upath=upath))
                                else:
                                    cookie_string = " ".join("{}={}".format(*i) for i in cookie_dict.items())
                                    fuzz_cmds.append(c.getCmd("web", "paramethCookie", url=url, cookies=cookie_string, upath=upath))
                            except requests.exceptions.ConnectionError as ce_error:
                                print("Connection Error: ", ce_error)
                                break
                            except requests.exceptions.Timeout as t_error:
                                print("Connection Timeout Error: ", t_error)
                                break
                            except requests.exceptions.RequestException as req_err:
                                print("Some Ambiguous Exception:", req_err)
                                break
                if len(fuzz_cmds) != 0:
                    print(f"{fg.li_cyan}Fuzzing .php Params ! {fg.rs}")
                    for i in fuzz_cmds:
                        print(f"[{fg.li_green}+{fg.rs}] {i}")
                        self.loginator(i)
                        call(i, shell=True)
                # self.processes = tuple(fuzz_cmds)
