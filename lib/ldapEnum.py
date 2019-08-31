#!/usr/bin/env python3

import os
from sty import fg, bg, ef, rs
from lib import nmapParser
from subprocess import call


class LdapEnum:
    def __init__(self, target):
        self.target = target
        self.processes = ""

    def ldapSearch(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        ldap_ports = np.ldap_ports
        if len(ldap_ports) == 0:
            pass
        else:
            ldap_enum = f"lib/ldap.sh {self.target}"
            call(ldap_enum, shell=True)

    def Scan(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        ldap_ports = np.ldap_ports
        if len(ldap_ports) == 0:
            pass
        else:
            if not os.path.exists(f"{self.target}-Report/ldap"):
                os.makedirs(f"{self.target}-Report/ldap")
            c = (
                fg.cyan
                + "Enumerating LDAP: Lightweight Directory Access Protocol, Running the following commands:"
                + fg.rs
            )
            print(c)
            string_ldap_ports = ",".join(map(str, ldap_ports))
            commands = (
                f"nmap -vv -Pn -sV -p {string_ldap_ports} --script='(ldap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)' -oA {self.target}-Report/nmap/ldap {self.target}",
                f"enum4linux -a -M -l -d {self.target} | tee {self.target}-Report/ldap/ldapenum4linux.txt",
            )
            self.processes = commands
