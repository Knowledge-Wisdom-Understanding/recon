#!/usr/bin/env python3

import os
from subprocess import call, check_output, STDOUT
from utils import config_parser
from utils import helper_lists
from urllib.parse import urlsplit
from sty import fg, rs
import requests


class ParamFuzzer:
    """This Class, DirsearchURLS is reponsible for sorting all the found URL's
    from Dirsearches report output and then it will combined them in to one unique
    list that will be fed to Aquatone to generate a nice HTML report that will
    Be opened up in the firefox web browser."""

    def __init__(self, target):
        self.target = target
        self.processes = []

    def fuzzMaster(self):
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
                    pass
                if len(php_urls) != 0 and (len(php_urls) < 10):
                    for url in php_urls:
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
                if len(fuzz_cmds) != 0:
                    for i in fuzz_cmds:
                        print(i)
                        call(i, shell=True)
                # self.processes = tuple(fuzz_cmds)
