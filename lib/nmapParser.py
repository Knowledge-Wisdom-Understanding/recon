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
        self.proxy_ports = []
        self.ssh_ports = []
        self.oracle_tns_ports = []
        self.ftp_ports = []
        self.smtp_ports = []
        self.ldap_ports = []
        self.java_rmi_ports = []
        self.cups_ports = []
        self.rpc_ports = []
        self.nfs_ports = []
        self.udp_ports = []

    def openPorts(self):
        report = NmapParser.parse_fromfile(
            f"{self.target}-Report/nmap/top-ports-{self.target}.xml"
        )
        self.nmap_services += report.hosts[0].services
        self.nmap_services = sorted(self.nmap_services, key=lambda s: s.port)
        # print(self.nmap_services)
        ignored_windows_http_ports = [5985, 47001]
        for service in self.nmap_services:
            if "open" not in service.state:
                continue
            self.services.append(
                (service.port, service.service, service.tunnel, service.cpelist)
            )
            for service in self.services:
                if service[0] not in self.tcp_ports:
                    self.tcp_ports.append(service[0])
                if "ssl" in service[2]:
                    if service[0] not in self.ssl_ports:
                        self.ssl_ports.append(service[0])
                if "http" in service[1]:
                    if "ssl" not in service[2]:
                        if service[0] not in ignored_windows_http_ports:
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
                if "http-proxy" in service[1]:
                    if service[0] not in self.proxy_ports:
                        self.proxy_ports.append(service[0])
                if "ssh" in service[1]:
                    if service[0] not in self.ssh_ports:
                        self.ssh_ports.append(service[0])
                if "oracle-tns" in service[1]:
                    if service[0] != 49160:
                        if service[0] not in self.oracle_tns_ports:
                            self.oracle_tns_ports.append(service[0])
                if "ftp" in service[1]:
                    if service[0] not in self.ftp_ports:
                        self.ftp_ports.append(service[0])

        # print("HTTP PORTS:", self.http_ports)
        # print("ORACLE PORTS:", self.oracle_tns_ports)
        # print("OPEN TCP PORTS:", self.tcp_ports)
        # print("SSL:", self.ssl_ports)
        # print("SMB:", self.smb_ports)
        # print("DNS:", self.dns_ports)
        # print("Services:", self.services)
        # print("SSH:", self.ssh_ports)
        # print("Proxy Ports:", self.proxy_ports)
