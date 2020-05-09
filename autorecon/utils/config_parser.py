#!/usr/bin/env python3

from string import Template
import yaml
import os


class CommandParser:
    def __init__(self, config_path, target):
        self.pwd = f"{os.path.dirname(os.path.realpath(__file__))}/../"
        self.target = target
        self.reportDir = f"""{os.path.expanduser('~')}/.local/share/autorecon/reports/{target}"""
        self.nmapReportDir = f"{self.reportDir}/nmap"
        try:
            with open(f"{config_path}", "r") as c:
                self.config = yaml.load(c, Loader=yaml.Loader)
        except FileNotFoundError as fnf_error:
            print(fnf_error)
            exit()

    def getPath(self, service, path, **kwargs):
        kwargs["pwd"] = self.pwd
        kwargs["target"] = self.target
        kwargs["reportDir"] = self.reportDir
        kwargs["nmapReportDir"] = self.nmapReportDir
        tmpl = Template(self.config['paths'][service][path])
        return tmpl.substitute(kwargs)

    def getCmd(self, service, path, **kwargs):
        kwargs["pwd"] = self.pwd
        kwargs["target"] = self.target
        kwargs["reportDir"] = self.reportDir
        kwargs["nmapReportDir"] = self.nmapReportDir
        tmpl = Template(self.config['commands'][service][path])
        return tmpl.substitute(kwargs)
