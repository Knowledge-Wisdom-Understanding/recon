#!/usr/bin/env python3

import os

# from multiprocessing import Pool
import time
from sty import fg, bg, ef, rs, RgbFg
from lib import nmapParser
from lib import enumWebSSL
from subprocess import call


class DnsEnum:
    def __init__(self, target):
        self.target = target
        self.processes = ""
        # self.domains = ""
        # self.domainName = []

    def Scan(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        dnsPort = np.dns_ports
        if len(dnsPort) == 0:
            pass
        else:
            if not os.path.exists("{}-Report/dns".format(self.target)):
                os.makedirs("{}-Report/dns".format(self.target))

            webssl = enumWebSSL.EnumWebSSL(self.target)
            webssl.getDomainName()
            dns1 = webssl.domainName
            altdns = webssl.altDomainNames
            dns = dns1 + altdns
            print(dns)

            # dnsnoquotes = "[{0}]".format("".join(map(str, dns)))
            # print(str(dnsnoquotes))

            if len(dns) != 0:
                alldns = " ".join(map(str, dns))
                dig_command = "dig axfr @{} {} | tee {}-Report/dns/dig-{}-{}.log".format(
                    self.target, alldns, self.target, self.target, alldns
                )
                green_plus = fg.li_green + "+" + fg.rs
                cmd_info = "[" + green_plus + "]"
                print(cmd_info, dig_command)
                call(dig_command, shell=True)
                filterZoneTransferDomainsCMD = (
                    "grep -v ';' {}-Report/dns/dig-{}-{}.log ".format(
                        self.target, self.target, alldns
                    )
                    + "| grep -v -e '^[[:space:]]*$' "
                    + "| awk '{print $1}' "
                    + "| sed 's/.$//' | sort -u >{}-Report/dns/zonexfer-domains.log".format(
                        self.target
                    )
                )
                # print(filterZoneTransferDomainsCMD)
                call(filterZoneTransferDomainsCMD, shell=True)

                # for i in dns:
                commands = (
                    "dnsenum --dnsserver {} --enum -f /usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt -r {} | tee {}-Report/dns/dsnenum-{}-{}.log".format(
                        self.target, dns[0], self.target, self.target, dns[0]
                    ),
                    # "gobuster dns -d {} -w /usr/share/seclists/Discovery/DNS/subdomains-top1mil-5000.txt -t 80 -o {}-Report/dns/gobuster-{}-{}.log".format(
                    #     i, self.target, self.target, i
                    # ),
                )
                for cmd in commands:
                    print(cmd_info, cmd)
                    # call(cmd, shell=True)
                self.processes = commands
                # self.domains = dns
