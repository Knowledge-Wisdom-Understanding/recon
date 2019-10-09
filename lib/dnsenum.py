#!/usr/bin/env python3

import os
import re
from sty import fg, bg, ef, rs
from lib import nmapParser
from lib import domainFinder
from utils import dig_parser
from utils import config_parser
from utils import helper_lists


class DnsEnum:
    """DnsEnum Class will Enumerate Dns Servers and Host names found thoughout the scanning process, most notably, hostnames that
    are discovered from the lib/domainFinder.py and the lib/dnsCrawl.py files. Also, There are some helper functions to
    export if you will, found hostnames that will be later used by the Web Enumeration Classes and functions."""

    def __init__(self, target):
        self.target = target
        self.processes = ""
        self.hostnames = []
        self.heartbleed = False

    def Scan(self):
        """Enumerate DNS server if any hostnames are found from lib/domainFinder.py and if
        port 53 is open."""
        print(fg.cyan + "Checking For Virtual Host Routing and DNS" + fg.rs)
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        dnsPorts = np.dns_ports
        dn = domainFinder.DomainFinder(self.target)
        dn.Scan()
        redirect_hostname = dn.redirect_hostname
        fqdn_hostname = dn.fqdn_hostname
        c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
        commands = []
        if len(redirect_hostname) != 0:
            for d in redirect_hostname:
                self.hostnames.append(d)
        if len(fqdn_hostname) != 0:
            for d in fqdn_hostname:
                self.hostnames.append(d)
        if len(self.hostnames) != 0 and (len(dnsPorts) != 0):
            if not os.path.exists(c.getPath("dns", "dnsDir")):
                os.makedirs(c.getPath("dns", "dnsDir"))
            if not os.path.exists(c.getPath("web", "aquatoneDir")):
                os.makedirs(c.getPath("web", "aquatoneDir"))

            # string_hosts = " ".join(map(str, self.hostnames))
            basename = []
            for host in self.hostnames:
                basename.append(".".join(host.split('.')[-2:]))
            unique_hosts = sorted(set(basename))
            for host in unique_hosts:
                commands.append(c.getCmd("dns", "dnsenum", hosts=host))
                # commands.append(c.getCmd("dns", "vhost", hosts=host))

        self.processes = tuple(commands)

    def GetHostNames(self):
        """This Function is for HTTPS/SSL enumWebSSL Class to enumerate found hostnames."""
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        ssl_ports = np.ssl_ports
        dnsPort = np.dns_ports
        c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
        ig = helper_lists.ignoreDomains()
        ignore = ig.ignore
        allsortedhostnameslist = []
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
            sdns = sorted(set(dns))
            tmpdns = []
            for x in sdns:
                tmpdns.append(x)
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
            for x in allsortedhostnames:
                allsortedhostnameslist.append(x)
        else:
            for sslport in ssl_ports:
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
                            if (
                                line.rstrip("\n") == "TLS 1.2 vulnerable to heartbleed"
                                or (line.rstrip("\n") == "TLS 1.1 vulnerable to heartbleed")
                                or (line.rstrip("\n") == "TLS 1.0 vulnerable to heartbleed")
                            ):
                                self.heartbleed = True

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
                        tmpdns2.append(x)

                    unsortedhostnames = []
                    for x in tmpdns2:
                        unsortedhostnames.append(x)
                    allsortedhostnames = sorted(set(tmpdns2))
                    allsortedhostnameslist = []
                    for x in allsortedhostnames:
                        allsortedhostnameslist.append(x)

        if len(dnsPort) == 0:
            if len(allsortedhostnameslist) != 0:
                for x in allsortedhostnameslist:
                    self.hostnames.append(x)

        else:
            ######## Check For Zone Transfer ###############
            if not os.path.exists(c.getPath("dns", "dnsDir")):
                os.makedirs(c.getPath("dns", "dnsDir"))
            dig_cmd = f"""dig -x {self.target} @{self.target}"""
            dp = dig_parser.digParse(self.target, dig_cmd)
            dp.parseDig()
            dig_hosts = dp.hosts
            sub_hosts = dp.subdomains
            if len(dig_hosts) != 0:
                for x in dig_hosts:
                    self.hostnames.append(x)
            if len(sub_hosts) != 0:
                for x in sub_hosts:
                    self.hostnames.append(x)
            if len(self.hostnames) != 0:
                alldns = " ".join(map(str, self.hostnames))
                zonexferDns = []
                dig_command = f"""dig axfr @{self.target} {alldns}"""
                dp2 = dig_parser.digParse(self.target, dig_command)
                dp2.parseDigAxfr()
                subdomains = dp2.subdomains
                for x in subdomains:
                    zonexferDns.append(x)
                sortedAllDomains = sorted(set(zonexferDns))
                for x in sortedAllDomains:
                    self.hostnames.append(x)
