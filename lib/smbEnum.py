#!/usr/bin/env python3

import os
from sty import fg, bg, ef, rs
from lib import nmapParser
from utils import config_paths


class SmbEnum:
    """SmbEnum Will Run the Following tools if port 139, or 445 are found
    open from nmap's initial scan results.
    SMBCLIENT, NMBLOOKUP, NBTSCAN, SMBSCAN, AND ENUM4LINUX"""

    def __init__(self, target):
        self.target = target
        self.processes = ""

    def Scan(self):
        """This Scan() Funciton will run the following tools,
        SMBCLIENT, NMBLOOKUP, NBTSCAN, SMBSCAN, AND ENUM4LINUX"""
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        smb_ports = np.smb_ports
        if len(smb_ports) == 0:
            pass
        else:
            c = config_paths.Configurator(self.target)
            c.createConfig()
            c.cmdConfig()
            green = fg.li_green
            reset = fg.rs
            cmd_info = "[" + green + "+" + reset + "]"
            if not os.path.exists(f"""{c.getPath("smbDir")}"""):
                os.makedirs(f"""{c.getPath("smbDir")}""")
            print(
                fg.cyan
                + "Enumerating NetBios SMB Samba Ports, Running the following commands:"
                + fg.rs
            )
            commands = (
                f"""echo {cmd_info} {green} 'smbclient -L //{self.target} -U 'guest'% | tee -a {c.getPath("smbScan")}' {reset}""",
                f"""smbclient -L //{self.target} -U 'guest'% | tee -a {c.getPath("smbScan")}""",
                f"""echo {cmd_info} {green} 'nmblookup -A {self.target} | tee -a {c.getPath("smbScan")}' {reset}""",
                f"""nmblookup -A {self.target} | tee -a {c.getPath("smbScan")}""",
                f"""echo {cmd_info} {green} '{c.getCmd("nmapSMB")} -oA {c.getPath("nmapSmb")} {self.target} | tee -a {c.getPath("smbScan")}' {reset}""",
                f"""{c.getCmd("nmapSMB")} -oA {c.getPath("nmapSmb")} {self.target} | tee -a {c.getPath("smbScan")}""",
                f"""echo {cmd_info} {green} 'nbtscan -rvh {self.target} | tee -a {c.getPath("smbScan")}' {reset}""",
                f"""nbtscan -rvh {self.target} | tee -a {c.getPath("smbScan")}""",
                f"""echo {cmd_info} {green} 'smbmap -H {self.target} | tee -a {c.getPath("smbScan")}' {reset}""",
                f"""smbmap -H {self.target} | tee -a {c.getPath("smbScan")}""",
                f"""echo {cmd_info} {green} 'smbmap -H {self.target} -R | tee -a {c.getPath("smbScan")}' {reset}""",
                f"""smbmap -H {self.target} -R | tee -a {c.getPath("smbScan")}""",
                f"""echo {cmd_info} {green} 'smbmap -u null -p "" -H {self.target} | tee -a {c.getPath("smbScan")}' {reset}""",
                f"""smbmap -u null -p "" -H {self.target} | tee -a {c.getPath("smbScan")}""",
                f"""echo {cmd_info} {green} 'smbmap -u null -p "" -H {self.target} -R | tee -a {c.getPath("smbScan")}' {reset}""",
                f"""smbmap -u null -p "" -H {self.target} -R | tee -a {c.getPath("smbScan")}""",
                f"""echo {cmd_info} {green} 'smbmap -u null -p "" -H {self.target} | tee -a {c.getPath("smbScan")}' {reset}""",
                f"""smbmap -u null -p "" -H {self.target} | tee -a {c.getPath("smbScan")}""",
                f"""echo {cmd_info} {green} 'enum4linux -av {self.target} | tee -a {c.getPath("smbScan")}' {reset}""",
                f"""enum4linux -av {self.target} | tee -a {c.getPath("smbScan")}""",
            )
            self.processes = commands
