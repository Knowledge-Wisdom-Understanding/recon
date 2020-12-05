#!/usr/bin/env python3

import requests
import re
# from bs4 import BeautifulSoup  # SoupStrainer
import urllib3
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
            for m in matches:
                if "*" not in m:
                    if ' ' in m:
                        disallow_dirs.append(m.lstrip("/").split(' ')[0])
                    else:
                        disallow_dirs.append(m.lstrip("/"))
            return disallow_dirs
        return None
