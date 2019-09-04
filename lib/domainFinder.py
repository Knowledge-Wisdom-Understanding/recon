#!/usr/bin/env python3

import os
from sty import fg, bg, ef, rs
from python_hosts.hosts import Hosts, HostsEntry
import re
from lib import nmapParser
from subprocess import call


class DomainFinder:
    def __init__(self, target):
        self.target = target
        self.redirect_hostname = []

    def Scan(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        ssl_ports = np.ssl_ports
        cmd_info = "[" + fg.green + "+" + fg.rs + "]"
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
            ".cgi",
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
                    # print(new)
                    matches = re.findall(
                        r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}", new
                    )
                    # print(matches)
                    for x in matches:
                        if not any(s in x for s in ignore):
                            dns.append(x)
                    if "|_http-title: Did not follow redirect to http:" in line:
                        # print(line)
                        split_line = line.split()
                        last_word = split_line[-1]
                        redirect_domain = (
                            last_word.replace("http://", "").replace("/", "").replace("'", "")
                        )
                        print(
                            f"{self.target} is redirecting to: {redirectDomain}, adding {redirectDomain} to /etc/hosts file"
                        )
                        dns.append(redirect_domain)
                        self.redirect_hostname.append(redirect_domain)
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
            if not os.path.exists(f"{self.target}-Report/webSSL"):
                os.makedirs(f"{self.target}-Report/webSSL")
            if not os.path.exists(f"{self.target}-Report/aquatone"):
                os.makedirs(f"{self.target}-Report/aquatone")
            for sslport in ssl_ports:
                sslscanCMD = f"sslscan https://{self.target}:{sslport} | tee {self.target}-Report/webSSL/sslscan-color-{self.target}-{sslport}.log"
                print(cmd_info, sslscanCMD)
                call(sslscanCMD, shell=True)
                if not os.path.exists(
                    f"{self.target}-Report/webSSL/sslscan-color-{self.target}-{sslport}.log"
                ):
                    pass
                else:
                    sslscanFile = (
                        f"{self.target}-Report/webSSL/sslscan-color-{self.target}-{sslport}.log"
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
                                alname2 = alname1.replace("DNS:", "").replace(",", "").split()
                                for x in alname2:
                                    altDomainNames.append(x)
                    # print(domainName)
                    # print(altDomainNames)
                    # print(alname2)
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

        dnsPort = np.dns_ports
        if len(dnsPort) == 0:
            if len(allsortedhostnameslist) != 0:
                for x in allsortedhostnameslist:
                    self.redirect_hostname.append(x)
                print(
                    f"{cmd_info} Adding {fg.li_cyan}{allsortedhostnameslist} {fg.rs}to /etc/hosts"
                )
                hosts = Hosts(path="/etc/hosts")
                new_entry = HostsEntry(
                    entry_type="ipv4", address=self.target, names=allsortedhostnameslist
                )
                hosts.add([new_entry])
                hosts.write()

        else:
            if not os.path.exists(f"{self.target}-Report/dns"):
                os.makedirs(f"{self.target}-Report/dns")
            ######## Check For Zone Transfer: Running dig ###############
            if len(allsortedhostnameslist) != 0:
                alldns = " ".join(map(str, allsortedhostnameslist))
                # print(alldns)
                dig_command = f"dig axfr @{self.target} {alldns} | tee {self.target}-Report/dns/dig-zonexfer-{self.target}.log"
                print(cmd_info, dig_command)
                call(dig_command, shell=True)
                filterZoneTransferDomainsCMD = (
                    f"grep -v ';' {self.target}-Report/dns/dig-zonexfer-{self.target}.log "
                    + "| grep -v -e '^[[:space:]]*$' "
                    + "| awk '{print $1}' "
                    + f"| sed 's/.$//' | sort -u >{self.target}-Report/dns/zonexfer-domains.log"
                )
                call(filterZoneTransferDomainsCMD, shell=True)
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
                        self.redirect_hostname.append(x)
                    if len(zonexferDns) != 0:
                        print(
                            f"{cmd_info} Adding {fg.li_cyan}{sortedAllDomainsList} {fg.rs}to /etc/hosts"
                        )
                        hosts = Hosts(path="/etc/hosts")
                        new_entry = HostsEntry(
                            entry_type="ipv4", address=self.target, names=sortedAllDomainsList
                        )
                        hosts.add([new_entry])
                        hosts.write()

    def getRedirect(self):
        """Extra Function for enumWeb HTTP hosts so as not to run Scan() twice."""
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
            ".cgi",
        ]
        try:
            with open(f"{self.target}-Report/nmap/top-ports-{self.target}.nmap", "r") as nm:
                for line in nm:
                    new = (
                        line.replace("=", " ")
                        .replace("/", " ")
                        .replace("commonName=", "")
                        .replace("/organizationName=", " ")
                    )
                    # print(new)
                    matches = re.findall(
                        r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}", new
                    )
                    # print(matches)
                    for x in matches:
                        if not any(s in x for s in ignore):
                            self.redirect_hostname.append(x)
                    if "|_http-title: Did not follow redirect to http:" in line:
                        print(line)
                        split_line2 = line.split()
                        last_word2 = split_line2[-1]
                        redirect_domainName = (
                            last_word2.replace("http://", "").replace("/", "").replace("'", "")
                        )
                        self.redirect_hostname.append(redirect_domainName)
        except FileNotFoundError as fnf_error:
            print(fnf_error)
