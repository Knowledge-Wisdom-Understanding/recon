#!/usr/bin/env python3

from string import Template
import yaml
from os import getcwd


class CommandParser:
    def __init__(self, config_path, target):
        self.pwd = getcwd()
        self.target = target
        self.reportDir = f"{getcwd()}/{target}-Report"
        self.nmapReportDir = f"{getcwd()}/{target}-Report/nmap"
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

    def webCmd(self, command, **kwargs):
        tmpl = Template(self.config['commands']['web'][command])
        return tmpl.substitute(kwargs)

    def webPath(self, path, **kwargs):
        tmpl = Template(self.config['paths']['web'][path])
        return tmpl.substitute(kwargs)

    def webSSLCmd(self, command, **kwargs):
        tmpl = Template(self.config['commands']['webSSL'][command])
        return tmpl.substitute(kwargs)

    def webSSLPath(self, path, **kwargs):
        tmpl = Template(self.config['paths']['webSSL'][path])
        return tmpl.substitute(kwargs)

    def dnsCmd(self, command, **kwargs):
        tmpl = Template(self.config['commands']['dns'][command])
        return tmpl.substitute(kwargs)

    def dnsPath(self, path, **kwargs):
        tmpl = Template(self.config['paths']['dns'][path])
        return tmpl.substitute(kwargs)

    def proxyCmd(self, command, **kwargs):
        tmpl = Template(self.config['commands']['proxy'][command])
        return tmpl.substitute(kwargs)

    def proxyPath(self, path, **kwargs):
        tmpl = Template(self.config['paths']['proxy'][path])
        return tmpl.substitute(kwargs)

    def wordlistPath(self, path, **kwargs):
        tmpl = Template(self.config['paths']['wordlists'][path])
        return tmpl.substitute(kwargs)

    def sshCmd(self, path, **kwargs):
        tmpl = Template(self.config['commands']['ssh'][path])
        return tmpl.substitute(kwargs)

    def sshPath(self, path, **kwargs):
        tmpl = Template(self.config['paths']['ssh'][path])
        return tmpl.substitute(kwargs)

    def nmapCmd(self, path, **kwargs):
        tmpl = Template(self.config['commands']['nmap'][path])
        return tmpl.substitute(kwargs)

    def nmapPath(self, path, **kwargs):
        tmpl = Template(self.config['paths']['nmap'][path])
        return tmpl.substitute(kwargs)
