#!/usr/bin/env python3

import os

# from multiprocessing import Pool
import time
from sty import fg, bg, ef, rs, RgbFg
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
            if not os.path.exists("{}-Report/smb".format(self.target)):
                os.makedirs("{}-Report/smb".format(self.target))
            c = (
                fg.cyan
                + "Enumerating NetBios SMB Samba Ports, Running the following commands:"
                + fg.rs
            )
            print(c)
            commands = (
                'smbclient -L //{} -U "guest"% | tee -a {}-Report/smb/smb-scan-{}.log'.format(
                    self.target, self.target, self.target
                ),
                "nmblookup -A {} | tee -a {}-Report/smb/smb-scan-{}.log".format(
                    self.target, self.target, self.target
                ),
                "nmap -vv -sV -Pn -p139,445 --script smb-enum-domains.nse,smb-enum-groups.nse,smb-enum-processes.nse,smb-enum-sessions.nse,smb-enum-shares.nse,smb-enum-users.nse,smb-ls.nse,smb-mbenum.nse,smb-os-discovery.nse,smb-print-text.nse,smb-psexec.nse,smb-security-mode.nse,smb-server-stats.nse,smb-system-info.nse,smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse --script-args=unsafe=1 -oA {}-Report/nmap/smbvulns-{} {} | tee -a {}-Report/smb/smb-scan-{}.log".format(
                    self.target, self.target, self.target, self.target, self.target
                ),
                "nbtscan -rvh {} | tee -a {}-Report/smb/smb-scan-{}.log".format(
                    self.target, self.target, self.target
                ),
                "smbmap -H {} | tee -a {}-Report/smb/smb-scan-{}.log".format(
                    self.target, self.target, self.target
                ),
                "smbmap -H {} -R | tee -a {}-Report/smb/smb-scan-{}.log".format(
                    self.target, self.target, self.target
                ),
                'smbmap -u null -p "" -H {} | tee -a {}-Report/smb/smb-scan-{}.log'.format(
                    self.target, self.target, self.target
                ),
                'smbmap -u null -p "" -H {} -R | tee -a {}-Report/smb/smb-scan-{}.log'.format(
                    self.target, self.target, self.target
                ),
                'smbmap -u null -p "" -H {} | tee -a {}-Report/smb/smb-scan-{}.log'.format(
                    self.target, self.target, self.target
                ),
                "enum4linux -av {} | tee -a {}-Report/smb/smb-scan-{}.log".format(
                    self.target, self.target, self.target
                ),
            )
            # c = fg.cyan + 'Enumerating SMB, Running the following commands:' + fg.rs
            # print(c)
            # green_plus = fg.li_green + '+' + fg.rs
            # cmd_info = '[' + green_plus + ']'
            # for command in commands:
            #     print(cmd_info, command)
            self.processes = commands
            # print(self.processes)
