#!/usr/bin/env python3

from string import Template
import yaml
from os import getcwd


class CommandParser:
    def __init__(self, config_path, target):
        self.pwd = getcwd()
        self.target = target
        self.reportDir = f"""{getcwd()}/{target}-Report"""
        self.nmapReportDir = f"""{getcwd()}/{target}-Report/nmap"""
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
