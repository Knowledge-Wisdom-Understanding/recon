#!/usr/bin/env python3

from autorecon.utils import config_parser
import requests
import re
# from bs4 import BeautifulSoup  # SoupStrainer
import urllib3
from os import path
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ParseRobots:
    def __init__(self, target, port, tls=False, althost=None):
        self.target = target
        self.port = port
        self.processes = ""
        self.cms_processes = ""
        self.proxy_processes = ""
        self.tls = tls
        self.althost = althost
        self.conf = config_parser.CommandParser(f"{path.expanduser('~')}/.config/autorecon/config.yaml", self.target)

    def get_url_path(self, robots=False):
        if self.tls is True:
            url_prefix = 'https://'
        else:
            url_prefix = 'http://'
        if self.althost:
            if robots:
                url = f"{url_prefix}{self.althost}:{self.port}/robots.txt"
            else:
                url = f"{url_prefix}{self.althost}:{self.port}"
        else:
            if robots:
                url = f"{url_prefix}{self.target}:{self.port}/robots.txt"
            else:
                url = f"{url_prefix}{self.target}:{self.port}"
        return url

    def check_robots(self):
        url = self.get_url_path(robots=True)

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
            for m in matches:
                if "*" not in m:
                    if ' ' in m:
                        disallow_dirs.append(m.lstrip("/").split(' ')[0])
                    else:
                        disallow_dirs.append(m.lstrip("/"))
            _disallow_dirs = [d.rstrip('/') for d in disallow_dirs]
            with open(self.conf.getPath("web", "aquatoneRobots"), "w") as ar:
                base_url = self.get_url_path()
                for d in _disallow_dirs:
                    ar.write(f"{base_url}/{d}"+"\n")

            ignore = ['CHANGELOG', 'install', 'MAINTAINERS', 'themes', 'includes', 'modules', 'UPGRADE', 'LICENSE', 'INSTALL', 'update']
            split_dirs = [path.splitext(d) for d in _disallow_dirs]
            crawl_dirs = []
            for d in split_dirs:
                if len(d) == 1 and d[0] not in ignore:
                    crawl_dirs.append(d)
                elif len(d) == 2 and '.' not in d[0] and "?" not in d[0] and "/" not in d[0] and d[0] not in ignore:
                    crawl_dirs.append(d[0])
                elif len(d) == 2 and '.' in d[0]:
                    continue

            if len(crawl_dirs) <= 10:
                return crawl_dirs
            else:
                return None
        return None
