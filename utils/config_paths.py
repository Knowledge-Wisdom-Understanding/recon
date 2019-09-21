#!/usr/bin/env python3

import os
from jinja2 import Environment, FileSystemLoader


class Configurator:
    def __init__(self, target):
        self.target = target
        self.config = dict()
        self.cmd = dict()

    def getPath(self, path):
        return self.config["paths"][path]

    def createConfig(self):
        pwd = os.getcwd()
        reportDir = f"{pwd}/{self.target}-Report"
        nmapReportDir = f"{pwd}/{self.target}-Report/nmap"
        self.config["target"] = {"target": self.target}

        env = Environment(loader=FileSystemLoader("config"))
        template = env.get_template("configurator_paths.j2")
        paths_string = template.render(
            reportDir=reportDir,
            nmapReportDir=nmapReportDir,
            target=self.target,
            pwd=pwd,
        )
        self.config["paths"] = dict()
        for path in paths_string.splitlines():
            key = path.split(":")[0].replace(" ", "")
            value = path.split(":")[1].replace(" ", "")
            self.config["paths"][key] = value

    def getCmd(self, cmd):
        return self.cmd["commands"][cmd]

    def cmdConfig(self):
        pwd = os.getcwd()
        self.cmd["target"] = {"target": self.target}

        env = Environment(loader=FileSystemLoader("config"))
        template = env.get_template("commands.j2")
        cmd_string = template.render(target=self.target, pwd=pwd)
        self.cmd["commands"] = dict()
        for cmd in cmd_string.splitlines():
            key = cmd.split("!")[0].replace(" ", "")
            value = cmd.split("!")[1].lstrip(" ")
            self.cmd["commands"][key] = value
