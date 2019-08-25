#!/usr/bin/env python3

import os
from subprocess import call
from multiprocessing import Pool
from functools import partial
from sty import fg, bg, ef, rs, RgbFg
from lib import nmapParser
from lib import dnsenum

# import subprocess as s
from python_hosts.hosts import Hosts, HostsEntry


class EnumWebSSL:
    def __init__(self, target):
        self.target = target
        self.processes = ""
        self.domainName = []
        self.altDomainNames = []

    def Scan(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        ssl_ports = np.ssl_ports

        def parseDomains(self):
            print("TODO")

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
                # call(sslscanCMD, shell=True)
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
                                alname2 = alname1.replace("DNS:", "").replace(",", "")
                                altDomainNames.append(alname2)
                    print(altDomainNames)
                    print(domainName)
                    # both = domainName + altDomainNames
                    # hosts = Hosts(path="/etc/hosts")
                    # new_entry = HostsEntry(
                    #     entry_type="ipv4", address=self.target, names=both
                    # )
                    # hosts.add([new_entry])
                    # hosts.write()

                    # print(domainName)
            if len(domainName) == 0:
                for sslport in ssl_ports:
                    commands = (
                        "whatweb -v -a 3 https://{}:{} >{}-Report/web/whatweb-{}-{}.txt".format(
                            self.target, sslport, self.target, self.target, sslport
                        ),
                        "wafw00f https://{}:{} >{}-Report/web/wafw00f-{}-{}.txt".format(
                            self.target, sslport, self.target, self.target, sslport
                        ),
                        "curl -sSik https://{}:{}/robots.txt -m 10 -o {}-Report/web/robots-{}-{}.txt &>/dev/null".format(
                            self.target, sslport, self.target, self.target, sslport
                        ),
                        "python3 /opt/dirsearch/dirsearch.py -u https://{}:{} -t 50 -e php,asp,aspx,txt -x 403,500 -f --plain-text-report {}-Report/web/dirsearch-{}-{}.log".format(
                            self.target, sslport, self.target, self.target, sslport
                        ),
                        # 'python3 /opt/dirsearch/dirsearch.py -u https://{}:{} -t 50 -e php,asp,aspx -f -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x 403,500 --plain-text-resslport web/dirsearch-dlistsmall-{}-{}.log'
                        # .format(self.target, sslport, self.target, self.target, sslport),
                        "nikto -ask=no -host https://{}:{} -ssl  >{}-Report/web/niktoscan-{}-{}.txt 2>&1 &".format(
                            self.target, sslport, self.target, self.target, sslport
                        ),
                    )
            else:
                info = fg.cyan + "Enumerating DNS, Checking for Zone-Transfer" + fg.rs
                print(info)
                dn = dnsenum.DnsEnum(self.target)
                dn.Scan()
                dns_enum_commands = dn.processes
                # for command in dns_enum_commands:
                #     print(cmd_info, command)
                # pool4 = Pool(2)
                # for i, returncode in enumerate(
                #     pool4.imap(partial(call, shell=True), dns_enum_commands)
                # ):
                #     if returncode != 0:
                #         print("{} command failed: {}".format(i, returncode))
                zxferFile = "{}-Report/dns/zonexfer-domains.log".format(self.target)
                if not os.path.exists(zxferFile):
                    pass
                    # for line in etchosts dns names do commands.
                else:
                    dns = []
                    with open(zxferFile, "r") as zf:
                        for line in zf:
                            dns.append(line.rstrip())
                    # dns = ",".join(map(str, dnsName))
                    print(dns)
                    if len(dns) != 0:
                        hosts = Hosts(path="/etc/hosts")
                        new_entry = HostsEntry(
                            entry_type="ipv4", address=self.target, names=dns
                        )
                        hosts.add([new_entry])
                        hosts.write()
                        commands = ()
                        for i in dns:
                            commands = commands + (
                                "whatweb -v -a 3 https://{}:{} >{}-Report/web/whatweb-{}-{}.txt".format(
                                    i, sslport, self.target, i, sslport
                                ),
                                "wafw00f https://{}:{} >{}-Report/web/wafw00f-{}-{}.txt".format(
                                    i, sslport, self.target, i, sslport
                                ),
                                "curl -sSik https://{}:{}/robots.txt -m 10 -o {}-Report/web/robots-{}-{}.txt &>/dev/null".format(
                                    i, sslport, self.target, i, sslport
                                ),
                                "python3 /opt/dirsearch/dirsearch.py -u https://{}:{} -t 50 -e php,asp,aspx,txt -x 403,500 -f --plain-text-report {}-Report/web/dirsearch-{}-{}.log".format(
                                    i, sslport, self.target, i, sslport
                                ),
                                # 'python3 /opt/dirsearch/dirsearch.py -u https://{}:{} -t 50 -e php,asp,aspx -f -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -x 403,500 --plain-text-resslport web/dirsearch-dlistsmall-{}-{}.log'
                                # .format(self.target, sslport, self.target, self.target, sslport),
                                "nikto -ask=no -host https://{}:{} -ssl  >{}-Report/web/niktoscan-{}-{}.txt 2>&1 &".format(
                                    i, sslport, self.target, i, sslport
                                ),
                            )

                        self.processes = commands
                    elif len(dns) == 0:
                        both = domainName + altDomainNames
                        hosts = Hosts(path="/etc/hosts")
                        new_entry = HostsEntry(
                            entry_type="ipv4", address=self.target, names=both
                        )
                        hosts.add([new_entry])
                        hosts.write()
            # c = fg.cyan + 'Enumerating HTTPS/SSL Ports, Running the following commands:' + fg.rs
            # print(c)
            # green_plus = fg.li_green + '+' + fg.rs
            # cmd_info = '[' + green_plus + ']'
            # for command in commands:
            #     print(cmd_info, command)
            # print("".join(domainName))
            # print(self.processes)

    def getDomainName(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        ssl_ports = np.ssl_ports
        if len(ssl_ports) == 0:
            pass
        else:
            https_string_ports = ",".join(map(str, ssl_ports))
            # print(https_string_ports)
            for sslport in ssl_ports:
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
                    # domainName = []
                    # altDomainNames = []
                    with open(sslscanFile, "rt") as f:
                        for line in f:
                            if "Subject:" in line:
                                nam = line.lstrip("Subject:").rstrip("\n")
                                name = nam.lstrip()
                                self.domainName.append(name)
                            if "Altnames:" in line:
                                anam = line.lstrip("Altnames:").rstrip("\n")
                                # print(anam)
                                aname = anam.lstrip()
                                # print(aname)
                                aname1 = aname.lstrip("DNS:")
                                # print(aname1)
                                aname2 = aname1.replace("DNS:", "").replace(",", "")
                                # print(aname2)
                                # aname3 = aname2.replace(" ", " , ")
                                # print(aname3)
                                # aname4 = aname3.replace(" ", "'")
                                # print(aname4)
                                self.altDomainNames.append(aname2)
                    # print(self.altDomainNames)
