#!/usr/bin/env python3

from subprocess import PIPE, Popen
from autorecon.utils import run_commands
from autorecon.utils import helper_lists
from collections.abc import Iterable
import re


class digParse:
    """The digParse Class will parse the output of a dig query against the target IP address
    along with a Zone Transer dig parser which is then appended to subdomains and hosts which
    will then be utilized by both domainFinder, enumDNS, and both enumWeb and enumWebSSL enumeration
    lib files."""

    def __init__(self, target, command):
        self.target = target
        self.command = command
        self.hosts = []
        self.subdomains = []

    def cmdline(self, command):
        """This cmdline method will also log commands using the loginator method from run_commands Since stdout is not displayed in the terminal. ToDo: Log Dig's output to a file"""
        rc = run_commands.RunCommands(self.target)
        rc.loginator(command)
        process = Popen(args=command, stdout=PIPE, shell=True)
        return process.communicate()[0]

    def parseDig(self):
        """parseDig will parse a simple dig query to the target IP address and append found hosts to self.hosts"""
        dig_output = [
            i.strip() for i in self.cmdline(self.command).decode("utf-8").split("\n")
        ]
        dig_filtered = [i.split() for i in dig_output if len(i) >= 9]
        domains = [
            i[-1]
            for i in dig_filtered
            if i[-2] in ["PTR", "MX", "NS", "CNAME", "TXT", "SOA"]
        ]
        unsorted_hosts = []
        for d in domains:
            unsorted_hosts.append(d.rstrip("."))
        sorted_hosts = sorted(set(unsorted_hosts))
        for d in sorted_hosts:
            if d.count(".") == 2:
                fqdn_name = d.split(".", 1)
            if d not in self.subdomains:
                if self.target not in self.subdomains:
                    self.subdomains.append(d)
            if len(fqdn_name) != 0:
                if fqdn_name not in self.hosts:
                    self.hosts.append(fqdn_name[1])

    def parseDigAxfr(self):
        """parseDigAxfr will perform a zone transer and append the results to self.subdomains list."""
        def flatten(lis):
            for item in lis:
                if isinstance(item, Iterable) and not isinstance(item, str):
                    for x in flatten(item):
                        yield x
                else:
                    yield item
        dig_output = [
            i.strip() for i in self.cmdline(self.command).decode("utf-8").split("\n")
        ]
        dig_filtered = [i.split() for i in dig_output if len(i) >= 9]
        domains = [
            i[0] and i[4::]
            for i in dig_filtered
            if i[-2] or i[-3] in ["PTR", "MX", "NS", "CNAME", "TXT", "SOA", "A"]
        ]
        unsorted_hosts = []
        domains = list(flatten(domains))
        for d in domains:
            unsorted_hosts.append(d.rstrip("."))
        sorted_hosts = sorted(set(unsorted_hosts))
        matches = [re.findall(r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{3,6}", x) for x in sorted_hosts]
        _sorted_hosts = []
        ig = helper_lists.ignoreDomains()
        ignore = ig.ignore
        matches = list(flatten(matches))
        for x in matches:
            if not any(s in x for s in ignore):
                _sorted_hosts.append(x)
        for d in _sorted_hosts:
            if d not in self.subdomains:
                self.subdomains.append(d)
