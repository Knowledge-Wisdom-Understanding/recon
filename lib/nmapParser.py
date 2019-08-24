#!/usr/bin/env python3

import os
import sys
from libnmap.parser import NmapParser
import subprocess as su


class NmapParserFunk:
    def __init__(self, target):
        self.target = target
        self.services = []
        self.tcp_ports = []
        self.http_ports = []
        self.ssl_ports = []
        self.smb_ports = []
        self.dns_ports = []
        self.nmap_services = []
        # self.servicesSC = []
        # self.nmap_servicesSC = []
        # self.nmap_scripts = []

    def openPorts(self):
        report = NmapParser.parse_fromfile(
            "{}-Report/nmap/top-ports-{}.xml".format(self.target, self.target)
        )
        self.nmap_services += report.hosts[0].services
        self.nmap_services = sorted(self.nmap_services, key=lambda s: s.port)
        # print(self.nmap_services)
        for service in self.nmap_services:
            if "open" not in service.state:
                continue
            self.services.append((service.port, service.service, service.tunnel))
            for service in self.services:
                if service[0] not in self.tcp_ports:
                    self.tcp_ports.append(service[0])
                if "ssl" in service[2]:
                    if service[0] not in self.ssl_ports:
                        self.ssl_ports.append(service[0])
                if "http" in service[1]:
                    if "ssl" not in service[2]:
                        if service[0] not in self.http_ports:
                            self.http_ports.append(service[0])
                if "netbios-ssn" in service[1]:
                    if service[0] not in self.smb_ports:
                        self.smb_ports.append(service[0])
                if "microsoft-ds" in service[1]:
                    if service[0] not in self.smb_ports:
                        self.smb_ports.append(service[0])
                if "domain" in service[1]:
                    if service[0] not in self.dns_ports:
                        self.dns_ports.append(service[0])

        # print("HTTP PORTS:", self.http_ports)
        # print("OPEN TCP PORTS:", self.tcp_ports)
        # print("SSL:", self.ssl_ports)
        # print("SMB:", self.smb_ports)
        # print("DNS:", self.dns_ports)
        # print("Services:", self.services)

    # def enumPorts(self):
    #     reportSC = NmapParser.parse_fromfile(
    #         "{}-Report/nmap/tcp-scripts-{}.xml".format(self.target, self.target)
    #     )
    #     self.nmap_servicesSC += reportSC.hosts[0].services
    #     self.nmap_servicesSC = sorted(self.nmap_servicesSC, key=lambda s: s.port)

    #     for service in self.nmap_servicesSC:

    #         if "open" not in service.state:
    #             continue
    #         self.servicesSC.append(
    #             (service.port, service.service, service.tunnel, service.scripts_results)
    #         )
    #         for service in self.servicesSC:
    #             if "ssl" in service[2]:
    #                 if service[3] not in self.nmap_scripts:
    #                     self.nmap_scripts.append(service[3])

    # newDict = {}
    # for line in self.nmap_scripts:
    #     newDict.update(line)
    # print(newDict)
    # print(self.nmap_scripts)

    # for serviceSC in self.nmap_servicesSC:
    #     if "open" not in serviceSC.state:
    #         continue
    #     self.servicesSC.append(
    #         (serviceSC.port, serviceSC.service, serviceSC.tunnel)
    #     )
    # for serviceSC in self.servicesSC:
    #     if serviceSC[0] not in self.tcp_ports:
    #         self.tcp_ports.append(service[0])
    #     if "ssl" in service[2]:
    #         if service[0] not in self.ssl_ports:
    #             self.ssl_ports.append(service[0])
    #     if "http" in service[1]:
    #         if "ssl" not in service[2]:
    #             if service[0] not in self.http_ports:
    #                 self.http_ports.append(service[0])
    #     if "netbios-ssn" in service[1]:
    #         if service[0] not in self.smb_ports:
    #             self.smb_ports.append(service[0])
    #     if "microsoft-ds" in service[1]:
    #         if service[0] not in self.smb_ports:
    #             self.smb_ports.append(service[0])
    # print(self.servicesSC)
