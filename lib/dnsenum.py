#!/usr/bin/env python3

import os
import re
from sty import fg, bg, ef, rs
from lib import nmapParser
from lib import domainFinder
from utils import dig_parser


class DnsEnum:
    def __init__(self, target):
        self.target = target
        self.processes = ""
        self.hostnames = []

    def Scan(self):
        info = fg.cyan + "Checking Virtual Host Routing and DNS" + fg.rs
        print(info)
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        dnsPorts = np.dns_ports
        dn = domainFinder.DomainFinder(self.target)
        dn.Scan()
        redirect_hostname = dn.redirect_hostname
        fqdn_hostname = dn.fqdn_hostname
        cwd = os.getcwd()
        reportDir = f"{cwd}/{self.target}-Report"
        if not os.path.exists(f"{self.target}-Report/dns"):
            os.makedirs(f"{self.target}-Report/dns")
        if not os.path.exists(f"{self.target}-Report/aquatone"):
            os.makedirs(f"{self.target}-Report/aquatone")

        commands = ()
        if len(redirect_hostname) != 0 and (len(dnsPorts) != 0):
            for d in redirect_hostname:
                self.hostnames.append(d)
            if len(fqdn_hostname) != 0:
                for d in fqdn_hostname:
                    self.hostnames.append(d)
                commands = commands + (
                    f"cd {reportDir} && dnsenum --dnsserver {self.target} --enum -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r {d} | tee {self.target}-Report/dns/dnsenum-{self.target}.log && cd - &>/dev/null",
                )
            else:
                string_hosts = " ".join(map(str, redirect_hostname))
                commands = commands + (
                    f"cd {reportDir} && dnsenum --dnsserver {self.target} --enum -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -r {string_hosts} | tee {self.target}-Report/dns/dnsenum-{self.target}.log && cd - &>/dev/null",
                )

        self.processes = commands

    def GetHostNames(self):
        """This Function is for HTTPS/SSL enumWebSSL Class to enumerate found hostnames."""
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        ssl_ports = np.ssl_ports
        dnsPort = np.dns_ports
        ignore = [
            ".nse",
            ".php",
            ".html",
            ".png",
            ".js",
            ".org",
            ".versio",
            ".com",
            ".gif",
            ".asp",
            ".aspx",
            ".jpg",
            ".jpeg",
            ".txt",
        ]
        dns = []
        try:
            with open(f"{self.target}-Report/nmap/top-ports-{self.target}.nmap", "r") as nm:
                for line in nm:
                    new = (
                        line.replace("=", " ")
                        .replace("/", " ")
                        .replace("commonName=", "")
                        .replace("/organizationName=", " ")
                    )
                    matches = re.findall(
                        r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}", new
                    )
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
            allsortedhostnameslist = []
            for x in allsortedhostnames:
                allsortedhostnameslist.append(x)
        else:
            for sslport in ssl_ports:
                if not os.path.exists(
                    f"{self.target}-Report/webSSL/sslscan-color-{self.target}-{sslport}.log"
                ):
                    pass
                else:
                    sslscanFile = "{}-Report/webSSL/sslscan-color-{}-{}.log".format(
                        self.target, self.target, sslport
                    )
                    domainName = []
                    altDomainNames = []
                    with open(sslscanFile, "rt") as f:
                        for line in f:
                            if "Subject:" in line:
                                n = line.lstrip("Subject:").rstrip("\n")
                                na = n.lstrip()
                                domainName.append(na)
                            if "Altnames:" in line:
                                alnam = line.lstrip("Altnames:").rstrip("\n")
                                alname = alnam.lstrip()
                                alname1 = alname.lstrip("DNS:")
                                alname2 = alname1.replace("DNS:", "").replace(",", "").split()
                                for x in alname2:
                                    altDomainNames.append(x)
                    both = []
                    for x in domainName:
                        both.append(x)
                    for x in altDomainNames:
                        both.append(x)

                    tmpdns2 = []
                    ignore_chars_regex = re.compile("[@_!#$%^&*()<>?/\|}{~:]")
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
            if not os.path.exists(f"{self.target}-Report/dns"):
                os.makedirs(f"{self.target}-Report/dns")
            dig_cmd = f"dig -x {self.target} @{self.target}"
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
                dig_command = f"dig axfr @{self.target} {alldns}"
                dp2 = dig_parser.digParse(self.target, dig_command)
                dp2.parseDigAxfr()
                subdomains = dp2.subdomains
                for x in subdomains:
                    zonexferDns.append(x)
                sortedAllDomains = sorted(set(zonexferDns))
                for x in sortedAllDomains:
                    self.hostnames.append(x)
