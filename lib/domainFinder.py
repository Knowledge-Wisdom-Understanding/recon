#!/usr/bin/env python3

import os
from sty import fg
from python_hosts.hosts import Hosts, HostsEntry
import re
from lib import nmapParser
from utils import dig_parser
from subprocess import call
from utils import config_parser
from utils import helper_lists


class DomainFinder:
    """DomainFinder Class will parse nmaps scripts output looking for hostnames, will also export and find
    the subject hostname returned by SSLSCAN if HTTPS/SSL web servers are found. All found hostnames will then be saved
    for later use in memory inside of this class by the Web and dnsenum classes / functions and features."""

    def __init__(self, target):
        self.target = target
        self.redirect_hostname = []
        self.fqdn_hostname = []

    def Scan(self):
        """Parse nmap's output from the top open ports scan and use regex to find valid hostnames that are
        3-6 chars in length. These domains will be filtered to ignore most .com and file extensions since this tool
        is currently designed for CTF machines like Hack the Box which usually have .htb extensions. The list of ignored domains
        is in utils/helper_lists.py"""
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        ssl_ports = np.ssl_ports
        dnsPort = np.dns_ports
        cmd_info = "[" + fg.li_green + "+" + fg.rs + "]"
        c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
        ig = helper_lists.ignoreDomains()
        ignore = ig.ignore
        dns = []
        try:
            with open(c.getPath("nmap", "nmap_top_ports_nmap"), "r") as nm:
                for line in nm:
                    new = (
                        line.replace("=", " ")
                        .replace("/", " ")
                        .replace("commonName=", "")
                        .replace("/organizationName=", " ")
                        .replace(",", " ")
                        .replace("_", " ")
                    )
                    matches = re.findall(r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{3,6}", new)
                    for x in matches:
                        if not any(s in x for s in ignore):
                            dns.append(x)
                    if "|_http-title: Did not follow redirect to http:" in line:
                        split_line = line.split()
                        last_word = split_line[-1]
                        redirect_domain = (
                            last_word.replace("http://", "")
                            .replace("/", "")
                            .replace("'", "")
                        )
                        print(f"""{self.target} is redirecting to: {redirect_domain}, adding {redirect_domain} to /etc/hosts file""")
                        dns.append(redirect_domain)
                        self.redirect_hostname.append(redirect_domain)
            sdns = sorted(set(dns))
            tmpdns = []
            for x in sdns:
                tmpdns.append(x)
                _ips = re.findall(r"[0-9]+(?:\.[0-9]+){3}", x)
                if len(_ips) > 0:
                    tmpdns.remove(x)
        except FileNotFoundError as fnf_error:
            print(fnf_error)
            exit()
        ################# SSLSCAN #######################
        if len(ssl_ports) == 0:
            tmpdns2 = []
            for x in tmpdns:
                tmpdns2.append(x)

            unsortedhostnames = []
            for x in tmpdns2:
                unsortedhostnames.append(x)
            allsortedhostnames = sorted(set(tmpdns2))
            allsortedhostnameslist = []
            for x in allsortedhostnames:
                allsortedhostnameslist.append(x)
        else:
            if not os.path.exists(c.getPath("webSSL", "webSSLDir")):
                os.makedirs(c.getPath("webSSL", "webSSLDir"))
            if not os.path.exists(c.getPath("web", "aquatoneDir")):
                os.makedirs(c.getPath("web", "aquatoneDir"))
            for sslport in ssl_ports:
                sslscanCMD = c.getCmd("webSSL", "sslscan", sslport=sslport)
                print(cmd_info, sslscanCMD)
                call(sslscanCMD, shell=True)
                if not os.path.exists(c.getPath("webSSL", "webSSLScanTarget", sslport=sslport)):
                    pass
                else:
                    sslscanFile = c.getPath("webSSL", "webSSLScanTarget", sslport=sslport)
                    domainName = []
                    altDomainNames = []
                    with open(sslscanFile, "rt") as f:
                        for line in f:
                            if "Subject:" in line:
                                n = line.lstrip("Subject:").rstrip("\n")
                                na = n.lstrip()
                                if na not in ignore:
                                    domainName.append(na)
                            if "Altnames:" in line:
                                alnam = line.lstrip("Altnames:").rstrip("\n")
                                alname = alnam.lstrip()
                                alname1 = alname.lstrip("DNS:")
                                alname2 = (
                                    alname1.replace("DNS:", "").replace(",", "").split()
                                )
                                for x in alname2:
                                    if x not in ignore:
                                        altDomainNames.append(x)
                    both = []
                    for x in domainName:
                        both.append(x)
                    for x in altDomainNames:
                        both.append(x)

                    tmpdns2 = []
                    ignore_chars_regex = re.compile(r"[@_!#$%^&*()<>?/\|}{~:]")
                    for x in both:
                        if ignore_chars_regex.search(x) == None:
                            tmpdns2.append(x)
                    for x in tmpdns:
                        if x not in ignore:
                            tmpdns2.append(x)

                    unsortedhostnames = []
                    for x in tmpdns2:
                        unsortedhostnames.append(x)
                    allsortedhostnames = sorted(set(tmpdns2))
                    allsortedhostnameslist = []
                    for x in allsortedhostnames:
                        if x not in ignore:
                            allsortedhostnameslist.append(x)
                    for x in allsortedhostnameslist:
                        ips = re.findall(r"[0-9]+(?:\.[0-9]+){3}", x)
                        if len(ips) > 0:
                            allsortedhostnameslist.remove(x)

        if len(dnsPort) == 0:
            if len(allsortedhostnameslist) != 0:
                for x in allsortedhostnameslist:
                    if x not in ignore:
                        self.redirect_hostname.append(x)
                print(f"""{cmd_info} Adding {fg.li_cyan}{allsortedhostnameslist} {fg.rs}to /etc/hosts""")
                hosts = Hosts(path="/etc/hosts")
                new_entry = HostsEntry(
                    entry_type="ipv4", address=self.target, names=allsortedhostnameslist
                )
                hosts.add([new_entry])
                hosts.write()

        else:
            if not os.path.exists(c.getPath("dns", "dnsDir")):
                os.makedirs(c.getPath("dns", "dnsDir"))
            dig_cmd = c.getCmd("dns", "dnsDig")
            print(cmd_info, dig_cmd)
            dp = dig_parser.digParse(self.target, dig_cmd)
            dp.parseDig()
            dig_hosts = dp.hosts
            sub_hosts = dp.subdomains
            if len(dig_hosts) != 0:
                for x in dig_hosts:
                    allsortedhostnameslist.append(x)
                    self.fqdn_hostname.append(x)
            if len(sub_hosts) != 0:
                for x in sub_hosts:
                    allsortedhostnameslist.append(x)

            ######## Check For Zone Transfer: Running dig ###############
            if len(allsortedhostnameslist) != 0:
                alldns = " ".join(map(str, allsortedhostnameslist))
                zonexferDns = []
                dig_command = c.getCmd("dns", "dnsDigAxfr", alldns=alldns)
                print(cmd_info, dig_command)
                dp2 = dig_parser.digParse(self.target, dig_command)
                dp2.parseDigAxfr()
                subdomains = dp2.subdomains
                for x in subdomains:
                    zonexferDns.append(x)
                sortedAllDomains = sorted(set(zonexferDns))
                sortedAllDomainsList = []
                for x in sortedAllDomains:
                    sortedAllDomainsList.append(x)
                    self.redirect_hostname.append(x)
                if len(zonexferDns) != 0:
                    print(f"""{cmd_info} Adding {fg.li_cyan}{sortedAllDomainsList} {fg.rs}to /etc/hosts""")
                    hosts = Hosts(path="/etc/hosts")
                    new_entry = HostsEntry(
                        entry_type="ipv4",
                        address=self.target,
                        names=sortedAllDomainsList,
                    )
                    hosts.add([new_entry])
                    hosts.write()

    def getRedirect(self):
        """Extra Function for enumWeb HTTP hosts so as not to run Scan() twice."""
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        dnsPort = np.dns_ports
        c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
        ig = helper_lists.ignoreDomains()
        ignore = ig.ignore
        try:
            with open(c.getPath("nmap", "nmap_top_ports_nmap"), "r") as nm:
                for line in nm:
                    new = (
                        line.replace("=", " ")
                        .replace("/", " ")
                        .replace("commonName=", "")
                        .replace("/organizationName=", " ")
                        .replace(",", " ")
                        .replace("_", " ")
                    )
                    matches = re.findall(r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{3,6}", new)
                    for x in matches:
                        if not any(s in x for s in ignore):
                            self.redirect_hostname.append(x)
                            _ips_ignore = re.findall(r"[0-9]+(?:\.[0-9]+){3}", x)
                            if len(_ips_ignore) > 0:
                                self.redirect_hostname.remove(x)
                    if "|_http-title: Did not follow redirect to http:" in line:
                        print(line)
                        split_line2 = line.split()
                        last_word2 = split_line2[-1]
                        redirect_domainName = (
                            last_word2.replace("http://", "")
                            .replace("/", "")
                            .replace("'", "")
                        )
                        self.redirect_hostname.append(redirect_domainName)
        except FileNotFoundError as fnf_error:
            print(fnf_error)
        if len(dnsPort) != 0:
            if not os.path.exists(c.getPath("dns", "dnsDir")):
                os.makedirs(c.getPath("dns", "dnsDir"))
            dig_cmd = c.getCmd("dns", "dnsDig")
            dp = dig_parser.digParse(self.target, dig_cmd)
            dp.parseDig()
            dig_hosts = dp.hosts
            sub_hosts = dp.subdomains
            if len(dig_hosts) != 0:
                for x in dig_hosts:
                    self.redirect_hostname.append(x)
            if len(sub_hosts) != 0:
                for x in sub_hosts:
                    self.redirect_hostname.append(x)
            if len(self.redirect_hostname) != 0:
                alldns = " ".join(map(str, self.redirect_hostname))
                zonexferDns = []
                dig_command = c.getCmd("dns", "dnsDigAxfr", alldns=alldns)
                dp2 = dig_parser.digParse(self.target, dig_command)
                dp2.parseDigAxfr()
                subdomains = dp2.subdomains
                for x in subdomains:
                    zonexferDns.append(x)
                sortedAllDomains = sorted(set(zonexferDns))
                for x in sortedAllDomains:
                    self.redirect_hostname.append(x)
