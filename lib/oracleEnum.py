#!/usr/bin/env python3

import os
from sty import fg, bg, ef, rs
from lib import nmapParser
from subprocess import call
from utils import config_paths


class OracleEnum:
    """OracleEnum Will Enumerate Oracle on it's default port of 1521. I've never seen oracle's vulnerable service running
    on different ports besides 1521 so the port is hard coded to avoid other oracle ports. Perhaps it would be best to eventually
    change this to have some logic in the nmapParser to also include other oracle ports. Time will tell."""

    def __init__(self, target):
        self.target = target
        self.processes = ""

    def OraclePwn(self):
        """OraclePwn will run a helper lib/oracle.sh bash script which will attempt to bruteforce
        Oracle if any valid SID's are found from the Scan() Functions results."""
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        oracle_tns_ports = np.oracle_tns_ports
        if len(oracle_tns_ports) == 0:
            pass
        else:
            ldap_enum = f"""lib/oracle.sh {self.target}"""
            call(ldap_enum, shell=True)

    def Scan(self):
        """This Scan() Function will run various oracle scanning tools and attempt to find
        valid SID's along with other useful information. The following tools will be used,
        Nmap, tnscmd10g, osscanner, and ODAT."""
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        oracle_tns_ports = np.oracle_tns_ports
        if len(oracle_tns_ports) == 0:
            pass
        else:
            c = config_paths.Configurator(self.target)
            c.createConfig()
            green = fg.li_green
            reset = fg.rs
            cmd_info = "[" + green + "+" + reset + "]"
            if not os.path.exists(f"""{c.getPath("oracleDir")}"""):
                os.makedirs(f"""{c.getPath("oracleDir")}""")
            print(
                fg.cyan + "Enumerating ORACLE, Running the following commands:" + fg.rs
            )
            # string_oracle_ports = ",".join(map(str, oracle_tns_ports))
            commands = (
                f"""echo {cmd_info} {green} 'nmap -sV -p 1521 --script oracle-enum-users.nse,oracle-sid-brute.nse,oracle-tns-version.nse -oA {c.getPath("nmaporacle")} {self.target}' {reset}""",
                f"""nmap -sV -p 1521 --script oracle-enum-users.nse,oracle-sid-brute.nse,oracle-tns-version.nse -oA {c.getPath("nmaporacle")} {self.target}""",
                f"""echo {cmd_info} {green} 'tnscmd10g ping -h {self.target} -p 1521 | tee {c.getPath("oraclelog")}' {reset}""",
                f"""tnscmd10g ping -h {self.target} -p 1521 | tee {c.getPath("oraclelog")}""",
                f"""echo {cmd_info} {green} 'tnscmd10g version -h {self.target} -p 1521 | tee {c.getPath("oraclelog")}' {reset}""",
                f"""tnscmd10g version -h {self.target} -p 1521 | tee {c.getPath("oraclelog")}""",
                f"""echo {cmd_info} {green} 'oscanner -v -s {self.target} -P 1521 | tee {c.getPath("oraclelog")}' {reset}""",
                f"""oscanner -v -s {self.target} -P 1521 | tee {c.getPath("oraclelog")}""",
                f"""echo {cmd_info} {green} './odat.py tnscmd -s {self.target} -p 1521 --ping | tee {c.getPath("oracletxt")}' {reset}""",
                f"""cd /opt/odat && ./odat.py tnscmd -s {self.target} -p 1521 --ping | tee {c.getPath("oracletxt")} && cd - &>/dev/null""",
                f"""echo {cmd_info} {green} './odat.py tnscmd -s {self.target} -p 1521 --version | tee {c.getPath("oracletxt")}' {reset}""",
                f"""cd /opt/odat && ./odat.py tnscmd -s {self.target} -p 1521 --version | tee {c.getPath("oracletxt")} && cd - &>/dev/null""",
                f"""echo {cmd_info} {green} './odat.py tnscmd -s {self.target} -p 1521 --status | tee {c.getPath("oracletxt")}' {reset}""",
                f"""cd /opt/odat && ./odat.py tnscmd -s {self.target} -p 1521 --status | tee {c.getPath("oracletxt")} && cd - &>/dev/null""",
                f"""echo {cmd_info} {green} './odat.py sidguesser -s {self.target} -p 1521 | tee {c.getPath("oraclesid")}' {reset}""",
                f"""cd /opt/odat && ./odat.py sidguesser -s {self.target} -p 1521 | tee {c.getPath("oraclesid")} && cd - &>/dev/null""",
            )
            self.processes = commands
