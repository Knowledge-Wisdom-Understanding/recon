#!/usr/bin/env python3

# import os
from python_hosts.hosts import Hosts, HostsEntry
import re
from lib import nmapParser


class DomainFinder:
    def __init__(self, target):
        self.target = target
        self.hostnames = []

    def Run():
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
        with open(
            "{}-Report/nmap/tcp-scripts-{}.nmap".format(self.target, self.target), "r"
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
        print(sdns)
        for x in sdns:
            self.hostnames.append(x)
        print(self.hostnames)

        if len(ssl_ports) == 0:
            pass
        else:
            if not os.path.exists("{}-Report/web".format(self.target)):
                os.makedirs("{}-Report/web".format(self.target))
            https_string_ports = ",".join(map(str, ssl_ports))
            # print(https_string_ports)
            for sslport in ssl_ports:
                sslscanCMD = "sslscan https://{}:{} | tee {}-Report/web/sslscan-color-{}-{}.log".format(
                    self.target, sslport, self.target, self.target, sslport
                )
                green_plus = fg.li_green + "+" + fg.rs
                cmd_info = "[" + green_plus + "]"
                print(cmd_info, sslscanCMD)
                call(sslscanCMD, shell=True)
                if not os.path.exists(
                    "{}-Report/web/sslscan-color-{}-{}.log".format(
                        self.target, self.target, sslport
                    )
                ):
                    pass
                else:
                    sslscanFile = "{}-Report/web/sslscan-color-{}-{}.log".format(
                        self.target, self.target, sslport
                    )
                    # print(sslscanFile)
                    domainName = []
                    altDomainNames = []
                    with open(sslscanFile, "rt") as f:
                        for line in f:
                            if "Subject:" in line:
                                n = line.lstrip("Subject:").rstrip("\n")
                                # print(n)
                                na = n.lstrip()
                                # print(na)
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
                    print(domainName)
                    print(altDomainNames)
                    # print(alname2)
                    both = []
                    for x in domainName:
                        both.append(x)
                    for x in altDomainNames:
                        both.append(x)

