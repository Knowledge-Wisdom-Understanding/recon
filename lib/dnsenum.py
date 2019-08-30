#!/usr/bin/env python3

import os

import re
from sty import fg, bg, ef, rs, RgbFg
from lib import nmapParser
from lib import domainFinder
from subprocess import call


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
        if not os.path.exists(f"{self.target}-Report/dns"):
            os.makedirs(f"{self.target}-Report/dns")
        if not os.path.exists(f"{self.target}-Report/aquatone"):
            os.makedirs(f"{self.target}-Report/aquatone")

        if len(redirect_hostname) and (len(dnsPorts) == 0):
            pass
        elif len(dnsPorts) == 0:
            pass
        elif redirect_hostname:
            commands = ()
            for d in redirect_hostname:
                self.hostnames.append(d)
                if "www" in d:
                    pass
                else:
                    commands = commands + (
                        f"dnsenum --dnsserver {self.target} --enum -f /usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt -r {d} | tee {self.target}-Report/dns/dnsenum-{self.target}-{d}.log",
                    )
                    self.processes = commands

    def GetHostNames(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        ssl_ports = np.ssl_ports
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
            with open(
                f"{self.target}-Report/nmap/top-ports-{self.target}.nmap", "r"
            ) as nm:
                for line in nm:
                    new = (
                        line.replace("=", " ")
                        .replace("/", " ")
                        .replace("commonName=", "")
                        .replace("/organizationName=", " ")
                    )
                    # print(new)
                    matches = re.findall(
                        r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}",
                        new,
                    )
                    # print(matches)
                    for x in matches:
                        if not any(s in x for s in ignore):
                            dns.append(x)
            # print(dns)
            sdns = sorted(set(dns))
            # print(sdns)
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
            https_string_ports = ",".join(map(str, ssl_ports))
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
                                alname2 = (
                                    alname1.replace("DNS:", "").replace(",", "").split()
                                )
                                for x in alname2:
                                    altDomainNames.append(x)
                    both = []
                    for x in domainName:
                        both.append(x)
                    for x in altDomainNames:
                        both.append(x)

                    tmpdns2 = []
                    for x in both:
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

        dnsPort = np.dns_ports
        if len(dnsPort) == 0:
            if len(allsortedhostnameslist) != 0:
                for x in allsortedhostnameslist:
                    self.hostnames.append(x)

        else:
            ######## Check For Zone Transfer from dig output ###############
            if len(allsortedhostnameslist) != 0:
                zxferFile = f"{self.target}-Report/dns/zonexfer-domains.log"
                if os.path.exists(zxferFile):
                    zonexferDns = []
                    with open(zxferFile, "r") as zf:
                        for line in zf:
                            zonexferDns.append(line.rstrip())
                    if len(allsortedhostnameslist) != 0:
                        for x in allsortedhostnameslist:
                            zonexferDns.append(x)
                    sortedAllDomains = sorted(set(zonexferDns))
                    sortedAllDomainsList = []
                    for x in sortedAllDomains:
                        sortedAllDomainsList.append(x)
                        self.hostnames.append(x)

