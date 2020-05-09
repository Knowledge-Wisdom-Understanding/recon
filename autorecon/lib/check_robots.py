#!/usr/bin/env python3

import os
from sty import fg
from autorecon.lib import nmapParser
from autorecon.lib import domainFinder
from subprocess import call
import glob
from autorecon.lib import vhostCrawl
from autorecon.utils import config_parser
from autorecon.utils import helper_lists
import requests
import re
# from bs4 import BeautifulSoup  # SoupStrainer


class ParseRobots:
    def __init__(self, target, port, tls=False, althost=None):
        self.target = target
        self.port = port
        self.processes = ""
        self.cms_processes = ""
        self.proxy_processes = ""
        self.tls = tls
        self.althost = althost

    def check_robots(self):
        if self.tls is True:
            url_prefix = 'https://'
        else:
            url_prefix = 'http://'
        if self.althost:
            url = f"{url_prefix}{self.althost}:{self.port}/robots.txt"
        else:
            url = f"{url_prefix}{self.target}:{self.port}/robots.txt"

        try:
            req = requests.get(url, verify=False)
            if req.status_code == 200:
                return req.text
            else:
                return None
        except requests.exceptions.ConnectionError as ce_error:
            print("Connection Error: ", ce_error)
            pass
        except requests.exceptions.Timeout as t_error:
            print("Connection Timeout Error: ", t_error)
            pass
        except requests.exceptions.RequestException as req_err:
            print("Some Ambiguous Exception:", req_err)
            pass

    def interesting_dirs(self):
        if self.check_robots():
            robots = self.check_robots()
            disallow_dirs = []
            regex = r"^\s*Disallow: (.*)"
            matches = re.findall(regex, robots, re.MULTILINE | re.IGNORECASE)
            if len(matches) < 5:
                for m in matches:
                    disallow_dirs.append(m.replace("/", ""))
                return disallow_dirs
            else:
                return None

    def testing(self):
        if self.interesting_dirs():
            all_dirs = self.interesting_dirs()
            print(all_dirs)


# c = ParseRobots('10.10.10.187', '80', althost='admirer.htb')
# c.interesting_dirs()
# c.testing()
