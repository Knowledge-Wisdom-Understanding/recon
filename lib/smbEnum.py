#!/usr/bin/env python3

import os
from sty import fg, bg, ef, rs
from lib import nmapParser


class SmbEnum:
    def __init__(self, target):
        self.target = target
        self.processes = ""

    def Scan(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        smb_ports = np.smb_ports
        if len(smb_ports) == 0:
            pass
        else:
            if not os.path.exists(f"{self.target}-Report/smb"):
                os.makedirs(f"{self.target}-Report/smb")
            c = (
                fg.cyan
                + "Enumerating NetBios SMB Samba Ports, Running the following commands:"
                + fg.rs
            )
            print(c)
            commands = (
                f"smbclient -L //{self.target} -U 'guest'% | tee -a {self.target}-Report/smb/smb-scan-{self.target}.log",
                f"nmblookup -A {self.target} | tee -a {self.target}-Report/smb/smb-scan-{self.target}.log",
                f"nmap -vv -sV -Pn -p139,445 --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse --script-args=unsafe=1 -oA {self.target}-Report/nmap/smbvulns-{self.target} {self.target} | tee -a {self.target}-Report/smb/smb-scan-{self.target}.log",
                f"nbtscan -rvh {self.target} | tee -a {self.target}-Report/smb/smb-scan-{self.target}.log",
                f"smbmap -H {self.target} | tee -a {self.target}-Report/smb/smb-scan-{self.target}.log",
                f"smbmap -H {self.target} -R | tee -a {self.target}-Report/smb/smb-scan-{self.target}.log",
                f'smbmap -u null -p "" -H {self.target} | tee -a {self.target}-Report/smb/smb-scan-{self.target}.log',
                f'smbmap -u null -p "" -H {self.target} -R | tee -a {self.target}-Report/smb/smb-scan-{self.target}.log',
                f'smbmap -u null -p "" -H {self.target} | tee -a {self.target}-Report/smb/smb-scan-{self.target}.log',
                f"enum4linux -av {self.target} | tee -a {self.target}-Report/smb/smb-scan-{self.target}.log",
            )
            self.processes = commands
            # print(self.processes)
