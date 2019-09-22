#!/usr/bin/env python3

import os
from jinja2 import Environment, FileSystemLoader


class Configurator:
    """The Configurator Class is used to parse the hard coded paths file. It is implemented
    Very poorly and not the proper jinja2 way at all. In fact, this implemetation breaks
    the core functionality of jinja2 and will be replaced by a better config file parser soon.
    As the time comes available to me or anyone that would like to contribute to the project.
    That being said, This Configurator does do the job, just not very well. """

    def __init__(self, target):
        self.target = target
        self.config = dict()
        self.cmd = dict()

    def getPath(self, path):
        """Return the path from the configurator_paths.j2 Dictionary."""
        return self.config["paths"][path]

    def createConfig(self):
        """Render the configurator_paths.j2 file."""
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
        """Return a cmd from the commands.j2 dictionary."""
        return self.cmd["commands"][cmd]

    def cmdConfig(self):
        """Render the commands.j2 template."""
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
