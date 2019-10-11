#!/usr/bin/env python3

import os
from sty import fg
from lib import nmapParser
from subprocess import call
from utils import config_parser


class LdapEnum:
    """LdapEnum Will Enumerate all found Ldap open ports using nmap and enum4linux and ldapsearch."""

    def __init__(self, target):
        self.target = target
        self.processes = ""

    def ldapSearch(self):
        """This will run a helper bash script that will attempt to login to smb
        using smbmap if any valid SambaNTHashes are found using a
        passthe hash technique."""
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        ldap_ports = np.ldap_ports
        if len(ldap_ports) == 0:
            pass
        else:
            ldap_enum = f"{os.getcwd()}/lib/ldap.sh {self.target}"
            call(ldap_enum, shell=True)

    def Scan(self):
        """If Ldap ports are open, run nmap ldap scripts, enum4linux and the results
        will be fed to the ldap.sh bash script."""
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        ldap_ports = np.ldap_ports
        if len(ldap_ports) == 0:
            pass
        else:
            c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
            if not os.path.exists(c.getPath("ldap", "ldapDir")):
                os.makedirs(c.getPath("ldap", "ldapDir"))
            print(fg.cyan + "Enumerating LDAP: Lightweight Directory Access Protocol, Running the following commands:" + fg.rs)
            string_ldap_ports = ",".join(map(str, ldap_ports))
            commands = []
            commands.append(c.getCmd("ldap", "nmapLdap", ldapPorts=string_ldap_ports))
            commands.append(c.getCmd("ldap", "enum4linuxLdap"))
            self.processes = tuple(commands)
