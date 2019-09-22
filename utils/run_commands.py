#!/usr/bin/env python3

from subprocess import PIPE, Popen, call
from tqdm import tqdm
from multiprocessing import Pool
from functools import partial
from termcolor import colored
from sty import fg, bg, ef, rs
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
from utils import remove_color
from utils import peaceout_banner
from utils import helper_lists


class RunCommands:
    """Helper Class to Wrap all commands in easy to access functions that can be called easily."""

    def __init__(self, target):
        self.target = target

    def mpRun(self, commands):
        """Pool all commands to run from each service class and run them 2 at a time.,"""
        if len(commands) != 0:
            with Pool(processes=2) as p:
                max_ = len(commands)
                with tqdm(total=max_) as pbar:
                    for i, returncode in enumerate(
                        p.imap_unordered(partial(call, shell=True), commands)
                    ):
                        pbar.update()
                        if returncode != 0:
                            print(f"{i} command failed: {returncode}")

    def infoMpRun(self, commands):
        """Pool all commmands to run from certain services and print the commands before running the Pool commands."""
        if len(commands) != 0:
            for command in commands:
                print(cmd_info, command)
            with Pool(processes=2) as p:
                max_ = len(commands)
                with tqdm(total=max_) as pbar:
                    for i, returncode in enumerate(
                        p.imap_unordered(partial(call, shell=True), commands)
                    ):
                        pbar.update()
                        if returncode != 0:
                            print(f"{i} command failed: {returncode}")

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

    def enumHTTP2(self):
        """Helper function to call the lib/enumWeb Large Wordlists Class."""
        eweb = enumWeb.EnumWeb(self.target)
        eweb.ScanWebOption()
        web_enum_commands = eweb.processes
        self.mpRun(web_enum_commands)

    def enumHTTPS2(self):
        """Helper function to call the lib/enumWebSSL Large Wordlists Class."""
        webssl = enumWebSSL.EnumWebSSL(self.target)
        webssl.ScanWebOption()
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
        self.infoMpRun(remaining_enum_cmds)

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
        self.infoMpRun(cms_commands)

    def cmsEnumSSL(self):
        """Helper funciton to call the CMS enumeration HTTPS logic."""
        cms = enumWebSSL.EnumWebSSL(self.target)
        cms.sslEnumCMS()
        cms_ssl_commands = cms.cms_processes
        self.infoMpRun(cms_ssl_commands)

    def proxyEnum(self):
        """Helper funciton to call The Check Proxy and Enumerate Proxy Class's / Functions."""
        pscan = enumProxy.CheckProxy(self.target)
        pscan.Scan()
        pr = nmapParser.NmapParserFunk(self.target)
        pr.openProxyPorts()
        pscan.Enum()
        proxy_commands = pscan.all_processes
        self.infoMpRun(proxy_commands)

    def proxyEnumCMS(self):
        """Helper funciton to call The Check Proxy and Enumerate Proxy CMS Class"""
        pcms = enumProxyCMS.EnumProxyCMS(self.target)
        pcms.proxyCMS()
        proxy_cms_commands = pcms.cms_processes
        self.infoMpRun(proxy_cms_commands)

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
