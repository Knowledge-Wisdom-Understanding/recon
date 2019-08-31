#!/usr/bin/env python3

import os
from sty import fg, bg, ef, rs
from lib import nmapParser
from subprocess import call


class OracleEnum:
    def __init__(self, target):
        self.target = target
        self.processes = ""

    def OraclePwn(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        oracle_tns_ports = np.oracle_tns_ports
        if len(oracle_tns_ports) == 0:
            pass
        else:
            ldap_enum = f"lib/oracle.sh {self.target}"
            call(ldap_enum, shell=True)

    def Scan(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        oracle_tns_ports = np.oracle_tns_ports
        if len(oracle_tns_ports) == 0:
            pass
        else:
            if not os.path.exists(f"{self.target}-Report/oracle"):
                os.makedirs(f"{self.target}-Report/oracle")
            c = fg.cyan + "Enumerating ORACLE, Running the following commands:" + fg.rs
            print(c)
            # string_oracle_ports = ",".join(map(str, oracle_tns_ports))
            commands = (
                f"nmap -sV -p 1521 --script oracle-enum-users.nse,oracle-sid-brute.nse,oracle-tns-version.nse -oA {self.target}-Report/nmap/oracle {self.target}",
                f"tnscmd10g ping -h {self.target} -p 1521 | tee {self.target}-Report/oracle/oracle.log",
                f"tnscmd10g version -h {self.target} -p 1521 | tee {self.target}-Report/oracle/oracle.log",
                f"oscanner -v -s {self.target} -P 1521 | tee {self.target}-Report/oracle/oracle.log",
                f"cd /opt/odat && ./odat.py tnscmd -s {self.target} -p 1521 --ping | tee {self.target}-Report/oracle/oracle.txt && cd - &>/dev/null",
                f"cd /opt/odat && ./odat.py tnscmd -s {self.target} -p 1521 --version | tee {self.target}-Report/oracle/oracle.txt && cd - &>/dev/null",
                f"cd /opt/odat && ./odat.py tnscmd -s {self.target} -p 1521 --status | tee {self.target}-Report/oracle/oracle.txt && cd - &>/dev/null",
                f"cd /opt/odat && ./odat.py sidguesser -s {self.target} -p 1521 | tee {self.target}-Report/oracle/oracle-sid.txt && cd - &>/dev/null",
            )
            self.processes = commands
