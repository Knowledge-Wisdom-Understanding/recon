#!/usr/bin/env python3

from subprocess import call
from tqdm import tqdm
from multiprocessing import Pool
from functools import partial
from sty import fg
from lib import topOpenPorts
from lib import nmapOpenPorts
from lib import nmapParser
from lib import enumWeb
from lib import enumWebSSL
from lib import smbEnum
from lib import dnsenum
from lib import aqua
from lib import enumProxy
from lib import ldapEnum
from lib import oracleEnum
from lib import searchsploits
from lib import enumProxyCMS
from lib import vhostCrawl
from lib import paramFuzz
from lib import ftp_anon
from utils import remove_color
from utils import peaceout_banner
from utils import helper_lists
from utils import config_parser
import psutil
import os
import signal
import logging


class RunCommands:
    """Helper Class to Wrap all commands in easy to access functions that can be called easily."""

    def __init__(self, target):
        self.target = target
        self.parent_pid = os.getpid()

    def loginator(self, executed_command):
        c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
        logging.basicConfig(
            filename=c.getPath("report", "commandLog"),
            format='%(asctime)s %(message)s',
            datefmt='%m/%d/%Y %I:%M:%S %p',
            level=logging.INFO
        )
        logging.info(f"[+] {executed_command} \n")

    def mpRun(self, commands):
        """Pool all commands to run from each service class and run them 2 at a time.,"""
        if len(commands) != 0:
            # parent_id = os.getpid()

            def worker_init():
                def sig_int(signal_num, frame):
                    parent = psutil.Process(self.parent_pid)
                    for child in parent.children():
                        if child.pid != os.getpid():
                            # print("Killing child process: ", child.pid)
                            child.kill()
                    # print("Killing Parent Process ID: ", parent.pid())
                    parent.kill()
                    psutil.Process(os.getpid()).kill()
                signal.signal(signal.SIGINT, sig_int)

            green = fg.li_green
            reset = fg.rs
            with Pool(2, worker_init) as p:
                try:
                    max_ = len(commands)
                    with tqdm(total=max_) as pbar:
                        for i, returncode in enumerate(
                            p.imap_unordered(partial(call, shell=True), commands)
                        ):
                            pbar.update()
                            pbar.write(f"[{green}+{reset}] {green}{commands[i]}{reset}")
                            pbar.set_description_str(desc=f"{fg.li_yellow}{commands[i].split()[:1]}{fg.rs}")
                            self.loginator(commands[i])
                            if returncode != 0:
                                print(f"{i} command failed: {returncode}")
                except KeyboardInterrupt:
                    p.close()
                    p.terminate()
                    p.join()

    def mpRunSploit(self, commands):
        """Pool all commands to run from each service class and run them 2 at a time.,"""
        if len(commands) != 0:
            parent_id = os.getpid()

            def worker_init():
                def sig_int(signal_num, frame):
                    parent = psutil.Process(parent_id)
                    for child in parent.children():
                        if child.pid != os.getpid():
                            # print("Killing child process: ", child.pid)
                            child.kill()
                    # print("Killing Parent Process ID: ", parent.pid())
                    parent.kill()
                    psutil.Process(os.getpid()).kill()
                signal.signal(signal.SIGINT, sig_int)

            green = fg.li_green
            reset = fg.rs
            with Pool(2, worker_init) as p:
                try:
                    max_ = len(commands)
                    with tqdm(total=max_) as pbar:
                        for i, returncode in enumerate(
                            p.imap_unordered(partial(call, shell=True), commands)
                        ):
                            pbar.update()
                            pbar.write(f"[{green}+{reset}] {green}{' '.join(commands[i].split()[-5:])}{reset}")
                            pbar.set_description_str(desc=f"{fg.li_yellow}{commands[i].split()[-5:-4]}{fg.rs}")
                            self.loginator(commands[i])
                            if returncode != 0:
                                print(f"{i} command failed: {returncode}")
                except KeyboardInterrupt:
                    p.close()
                    p.terminate()
                    p.join()

    def enumHTTP(self):
        """Helper function to call the lib/enumWeb Class."""
        eweb = enumWeb.EnumWeb(self.target)
        eweb.Scan()
        web_enum_commands = eweb.processes
        self.mpRun(web_enum_commands)

    def enumHTTPS(self):
        """Helper function to call the lib/enumWebSSL Class."""
        webssl = enumWebSSL.EnumWebSSL(self.target)
        webssl.Scan()
        web_ssl_enum_commands = webssl.processes
        self.mpRun(web_ssl_enum_commands)

    def enumDNS(self):
        """Helper function to call the lib/DnsEnum Class."""
        dn = dnsenum.DnsEnum(self.target)
        dn.Scan()
        dns_enum_commands = dn.processes
        self.mpRun(dns_enum_commands)

    def enumSMB(self):
        """Helper function to call the lib/SmbEnum Class."""
        smb = smbEnum.SmbEnum(self.target)
        smb.Scan()
        smb_enum_commands = smb.processes
        self.mpRun(smb_enum_commands)

    def enumRemainingServices(self):
        """Helper function to call the lib/NmapOpenPorts Class."""
        teal = fg.li_cyan
        reset = fg.rs
        print(f"{teal}Enumerating Remaining Services {reset}")
        nmapRemaing = nmapOpenPorts.NmapOpenPorts(self.target)
        nmapRemaing.Scan()
        remaining_enum_cmds = nmapRemaing.processes
        self.mpRun(remaining_enum_cmds)

    def getOpenPorts(self):
        """Helper function to call the lib/NmapParserFunk Class."""
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()

    def scanTopTcpPorts(self):
        """Helper function to call the lib/TopOpenPorts Class."""
        ntp = topOpenPorts.TopOpenPorts(self.target)
        ntp.Scan()

    def fullTcpAndTopUdpScan(self):
        """Helper function to Run FULLTCP and UDP and VULNERS nmap Scans."""
        ntp = topOpenPorts.TopOpenPorts(self.target)
        ntp.topUdpAllTcp()
        nmap_commands = ntp.processes
        self.mpRun(nmap_commands)

    def aquatone(self):
        """Helper Funtion to run Aquatone provided there are open web servers and found urls which is
        handled in the lib/aqua.py logic."""
        aq = aqua.Aquatone(self.target)
        aq.Scan()

    def peace(self):
        """Helper function to print the peaceout banner."""
        pe = peaceout_banner.PeaceOut()
        pe.bannerOut()

    def cmsEnum(self):
        """Helper funciton to call the CMS enumeration HTTP logic."""
        cm = enumWeb.EnumWeb(self.target)
        cm.CMS()
        cms_commands = cm.cms_processes
        self.mpRun(cms_commands)

    def cmsEnumSSL(self):
        """Helper funciton to call the CMS enumeration HTTPS logic."""
        cms = enumWebSSL.EnumWebSSL(self.target)
        cms.sslEnumCMS()
        cms_ssl_commands = cms.cms_processes
        self.mpRun(cms_ssl_commands)

    def proxyEnum(self):
        """Helper funciton to call The Check Proxy and Enumerate Proxy Class's / Functions."""
        pscan = enumProxy.CheckProxy(self.target)
        pscan.Scan()
        pr = nmapParser.NmapParserFunk(self.target)
        pr.openProxyPorts()
        pscan.Enum()
        proxy_commands = pscan.all_processes
        self.mpRun(proxy_commands)

    def proxyEnumCMS(self):
        """Helper funciton to call The Check Proxy and Enumerate Proxy CMS Class"""
        pcms = enumProxyCMS.EnumProxyCMS(self.target)
        pcms.proxyCMS()
        proxy_cms_commands = pcms.cms_processes
        self.mpRun(proxy_cms_commands)

    def enumLdap(self):
        """Helper Function to Call Ldap Enumeration."""
        ld = ldapEnum.LdapEnum(self.target)
        ld.Scan()
        ldap_cmds = ld.processes
        self.mpRun(ldap_cmds)
        ld.ldapSearch()

    def enumOracle(self):
        """Helper Function to Call Oracle Enumeration."""
        oc = oracleEnum.OracleEnum(self.target)
        oc.Scan()
        oracle_cmds = oc.processes
        self.mpRun(oracle_cmds)
        oc.OraclePwn()

    def getUdpPorts(self):
        """Helper Function to parse UDP ports."""
        udp = nmapParser.NmapParserFunk(self.target)
        udp.openUdpPorts()

    def searchSploits(self):
        """Helper Function to Call the Search Class which will attempt to run SearchSploit."""
        ss = searchsploits.Search(self.target)
        ss.Scan()
        searchsploit_cmds = ss.processes
        self.mpRunSploit(searchsploit_cmds)
        ss.vulnCheck()

    def sortFoundUrls(self):
        """Helper Function to call the Helper Class DirsearchURLS. See DirsearchURL's comment for more information."""
        ds = helper_lists.DirsearchURLS(self.target)
        ds.genDirsearchUrlList()

    def sortFoundProxyUrls(self):
        """Helper Function to sort found Proxy URLS found by dirsearch."""
        ds = helper_lists.DirsearchURLS(self.target)
        ds.genProxyDirsearchUrlList()

    def removeColor(self):
        """Helper function to call the utils/remove_color Class."""
        nocolor = remove_color.Clean(self.target)
        nocolor.listfiles()
        nocolor.listFilesProxy()

    def checkSource(self):
        sc = vhostCrawl.sourceCommentChecker(self.target)
        sc.extract_source_comments()

    def fuzzinator(self):
        fz = paramFuzz.ParamFuzzer(self.target)
        fz.fuzzMaster()
        # fuzz_cmds = fz.processes
        # self.mpRun(fuzz_cmds)

    def ftpAnonymous(self):
        ft = ftp_anon.FtpCheck(self.target)
        ft.anonymousLogin()

    def winrmPwn(self):
        ldwrm = ldapEnum.LdapEnum(self.target)
        ldwrm.PwnWinRM()
