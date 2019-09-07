#!/usr/bin/env python3

from subprocess import PIPE, Popen


class digParse:
    def __init__(self, target, command):
        self.target = target
        self.command = command
        self.hosts = []
        self.subdomains = []

    def cmdline(self, command):
        process = Popen(args=command, stdout=PIPE, shell=True)
        return process.communicate()[0]

    def parseDig(self):
        dig_output = [i.strip() for i in self.cmdline(self.command).decode("utf-8").split("\n")]
        dig_filtered = [i.split() for i in dig_output if len(i) > 10]
        domains = [
            i[-1] for i in dig_filtered if i[-2] in ["PTR", "MX", "NS", "CNAME", "TXT", "SOA"]
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
        dig_output = [i.strip() for i in self.cmdline(self.command).decode("utf-8").split("\n")]
        dig_filtered = [i.split() for i in dig_output if len(i) > 10]
        domains = [
            i[0] for i in dig_filtered if i[-2] in ["PTR", "MX", "NS", "CNAME", "TXT", "SOA", "A"]
        ]
        unsorted_hosts = []
        for d in domains:
            unsorted_hosts.append(d.rstrip("."))
        sorted_hosts = sorted(set(unsorted_hosts))
        for d in sorted_hosts:
            if d not in self.subdomains:
                self.subdomains.append(d)
