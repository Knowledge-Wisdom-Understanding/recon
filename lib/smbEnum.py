#!/usr/bin/env python3

import os
from sty import fg, bg, ef, rs
from lib import nmapParser
from utils import config_parser


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
            c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
            if not os.path.exists(c.getPath("smb", "smbDir")):
                os.makedirs(c.getPath("smb", "smbDir"))
            print(fg.cyan + "Enumerating NetBios SMB Samba Ports, Running the following commands:" + fg.rs)
            commands = []
            commands.append(c.getCmd("smb", "smbclient"))
            commands.append(c.getCmd("smb", "nmblookup"))
            commands.append(c.getCmd("smb", "nmapSmb"))
            commands.append(c.getCmd("smb", "nbtscan"))
            commands.append(c.getCmd("smb", "smbmapH"))
            commands.append(c.getCmd("smb", "smbmapHR"))
            commands.append(c.getCmd("smb", "smbmapNull"))
            commands.append(c.getCmd("smb", "smbmapNullR"))
            commands.append(c.getCmd("smb", "enum4linux"))
            self.processes = tuple(commands)
