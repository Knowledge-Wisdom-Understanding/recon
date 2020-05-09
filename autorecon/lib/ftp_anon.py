#!/usr/bin/env python3

import ftplib
import os
from sty import fg
from subprocess import call
from autorecon.utils import config_parser
from autorecon.lib import nmapParser


class FtpCheck:
    def __init__(self, target):
        self.target = target

    def anonymousLogin(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.allOpenPorts()
        ftpPorts = np.ftp_ports
        if len(ftpPorts) != 0:
            for port in ftpPorts:
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(self.target, port)
                    ftp.login('anonymous', '')
                    print(ftp.getwelcome())
                    ftp.set_pasv(1)
                    print(ftp.dir())
                    print(ftp.nlst())
                    print(f'\n[{fg.li_green}*{fg.rs}] ' + str(self.target) + f'{fg.white} FTP Anonymous Logon Succeeded!{fg.rs}')
                    self.ftpDownloadAll(port)
                except Exception as e:
                    print(str(e))
                    print(f'\n[{fg.li_red}!{fg.rs}] ' + str(self.target) + ' FTP Anonymous Logon Failed.')
                    return False

    def ftpDownloadAll(self, port):
        try:
            c = config_parser.CommandParser(f"{os.path.expanduser('~')}/.config/autorecon/config.yaml", self.target)
            if not os.path.exists(c.getPath("ftp", "ftpDir")):
                os.makedirs(c.getPath("ftp", "ftpDir"))
            if not os.path.exists(c.getPath("ftp", "anonDownloadPath")):
                os.makedirs(c.getPath("ftp", "anonDownloadPath"))
            cwd = os.getcwd()
            os.chdir(c.getPath("ftp", "anonDownloadPath"))
            wget_cmd = f"""wget -m --no-passive -c --read-timeout=5 --tries=5 ftp://anonymous:anonymous@{self.target}:{port}"""
            print(f"{fg.li_magenta}Downloading All Files from FTP Server on Port: {fg.rs}{port}")
            print(f"[{fg.li_green}+{fg.rs}] {wget_cmd}")
            print(f"{fg.li_yellow}")
            call(wget_cmd, shell=True)
            print(f"{fg.rs}")
            os.chdir(cwd)
        except IOError as e:
            print(e)
            return
