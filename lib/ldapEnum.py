#!/usr/bin/env python3

import os
from sty import fg, bg, ef, rs
from lib import nmapParser
from subprocess import call
from utils import config_paths


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
            ldap_enum = f"lib/ldap.sh {self.target}"
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
            green = fg.li_green
            reset = fg.rs
            cmd_info = "[" + green + "+" + reset + "]"
            c = config_paths.Configurator(self.target)
            c.createConfig()
            if not os.path.exists(f"""{c.getPath("ldapDir")}"""):
                os.makedirs(f"""{c.getPath("ldapDir")}""")
            print(
                fg.cyan
                + "Enumerating LDAP: Lightweight Directory Access Protocol, Running the following commands:"
                + fg.rs
            )
            string_ldap_ports = ",".join(map(str, ldap_ports))
            commands = (
                f"""echo {cmd_info} {green} 'nmap -vv -Pn -sV -p {string_ldap_ports} --script='(ldap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)' -oA {c.getPath("nmapLdap")} {self.target}' {reset}""",
                f"""nmap -vv -Pn -sV -p {string_ldap_ports} --script='(ldap* or ssl*) and not (brute or broadcast or dos or external or fuzzer)' -oA {c.getPath("nmapLdap")} {self.target}""",
                f"""echo {cmd_info} {green} 'enum4linux -a -M -l -d {self.target} | tee {c.getPath("ldapEnum4linux")}' {reset}""",
                f"""enum4linux -a -M -l -d {self.target} | tee {c.getPath("ldapEnum4linux")}""",
            )
            self.processes = commands
