#!/usr/bin/env python3

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
from lib import brute
from lib import searchsploits
from lib import enumProxyCMS
from utils import remove_color
from utils import peaceout_banner
from utils import helper_lists
from termcolor import colored
from sty import fg, bg, ef, rs
import argparse
import signal
import time
import sys
import random
import os
from subprocess import call
from multiprocessing import Pool
from functools import partial
import socket
from tqdm import tqdm

cmd_info = "[" + fg.li_green + "+" + fg.rs + "]"
bad_cmd = "[" + fg.li_red + "+" + fg.rs + "]"
green = fg.li_green
teal = fg.li_cyan
purp = fg.li_magenta
reset = fg.rs
cwd = os.getcwd()

if os.getuid() != 0:
    print(f"{bad_cmd} This program needs to be ran as root.")
    sys.exit()

intervals = (
    ("weeks", 604800),  # 60 * 60 * 24 * 7
    ("days", 86400),  # 60 * 60 * 24
    ("hours", 3600),  # 60 * 60
    ("minutes", 60),
    ("seconds", 1),
)

EXAMPLES = """
    Ex. python3 recon.py -t 10.10.10.10
    Ex. python3 recon.py -w 10.10.10.10
    Ex. python3 recon.py -f ips.txt
    Ex. python3 recon.py -t 10.10.10.10 -b ssh
    Ex. python3 recon.py -t 10.10.10.10 -b ssh -p 2222
    Ex. python3 recon.py -t 10.10.10.10 -b ssh -u bob -P /usr/share/seclists/Passwords/darkc0de.txt

"""


def banner():
    def random_color():
        valid_colors = ("red", "green", "yellow", "blue", "magenta", "cyan")
        return random.choice(valid_colors)

    autoRecon = """
       _____________          ____    ________________                               
      /___/___      \        /  / |  /___/__          \                   _____      
          /  /   _   \______/__/  |______|__|_____ *   \_________________/__/  |___  
       __/__/   /_\   \ |  |  \   __\/  _ \|  |       __/ __ \_/ ___\/  _ \|       | 
      |   |     ___    \|  |  /|  | (  |_| )  |    |   \  ___/\  \__(  |_| )   |   | 
      |___|____/\__\____|____/_|__|\_\____/|__|____|_  /\___  |\___  \____/|___|  /  
      gtihub.com/Knowledge-Wisdom-Understanding  \___\/  \__\/  \__\_/      \___\/   
        
"""

    def print_art(msg, color):
        colored_art = colored(msg, color=color)
        print(colored_art)

    color = random_color()
    print_art(autoRecon, color)


def display_time(seconds, granularity=2):
    result = []

    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            if value == 1:
                name = name.rstrip("s")
            result.append(f"{value} {name}")
    return ", ".join(result[:granularity])


def signal_handler(sig, frame):
    print(" ")
    print(f"{purp}See you Space Cowboy...{reset}")
    sys.exit(0)


VERSION = 2.0


def main():
    banner()
    startTimer = time.time()
    parser = argparse.ArgumentParser(
        conflict_handler="resolve",
        description="An Information Gathering and Enumeration Framework",
        usage="python3 recon.py -t 10.10.10.10",
    )
    parser.add_argument("-t", "--target", help="Single IPv4 Target to Scan")
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        help="Show Current Version",
        version=f"Version {VERSION}",
    )
    parser.add_argument("-f", "--file", help="File of IPv4 Targets to Scan")
    parser.add_argument(
        "-w",
        "--web",
        help="Get open ports for IPv4 address, then only Enumerate Web & and Dns Services",
    )
    parser.add_argument(
        "-b",
        "--brute",
        help="Experimental! - Brute Force ssh,smb,ftp, or http. -t, --target is REQUIRED. Must supply only one protocol at a time. Since there are already many stand-alone bruteforce tools out there, for ssh, first valid users will be enumerated before password brute is initiated, when no user or passwords are supplied as options.",
        choices=["ftp", "smb", "http", "ssh"],
    )
    parser.add_argument(
        "-p",
        "--port",
        help="port for brute forcing argument. If no port specified, default port will be used",
    )
    parser.add_argument(
        "-u",
        "--user",
        help="Single user name for brute forcing, for SSH, if no user specified, will default to wordlists/usernames.txt and bruteforce usernames",
    )
    parser.add_argument(
        "-U", "--USERS", help="List of usernames to try for brute forcing. Not yet implimented"
    )
    parser.add_argument("-P", "--PASSWORDS", help="List of passwords to try. Not required for SSH")

    args = parser.parse_args()

    def validateIP():
        try:
            s = socket.inet_aton(args.target)
        except socket.error:
            print("")
            print(f"{bad_cmd} Bad IP address")
            print("")
            sys.exit()

    def mpRun(commands):
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

    def removeColor():
        nocolor = remove_color.Clean(args.target)
        nocolor.listfiles()
        nocolor.listFilesProxy()

    def enumHTTP():
        eweb = enumWeb.EnumWeb(args.target)
        eweb.Scan()
        web_enum_commands = eweb.processes
        mpRun(web_enum_commands)

    def enumHTTPS():
        webssl = enumWebSSL.EnumWebSSL(args.target)
        webssl.Scan()
        web_ssl_enum_commands = webssl.processes
        mpRun(web_ssl_enum_commands)

    def enumHTTP2():
        eweb = enumWeb.EnumWeb(args.target)
        eweb.ScanWebOption()
        web_enum_commands = eweb.processes
        mpRun(web_enum_commands)

    def enumHTTPS2():
        webssl = enumWebSSL.EnumWebSSL(args.target)
        webssl.ScanWebOption()
        web_ssl_enum_commands = webssl.processes
        mpRun(web_ssl_enum_commands)

    def enumDNS():
        dn = dnsenum.DnsEnum(args.target)
        dn.Scan()
        dns_enum_commands = dn.processes
        mpRun(dns_enum_commands)

    def enumSMB():
        smb = smbEnum.SmbEnum(args.target)
        smb.Scan()
        smb_enum_commands = smb.processes
        mpRun(smb_enum_commands)

    def enumRemainingServices():
        print(f"{teal}Enumerating Remaining Services {reset}")
        nmapRemaing = nmapOpenPorts.NmapOpenPorts(args.target)
        nmapRemaing.Scan()
        remaining_enum_cmds = nmapRemaing.processes
        mpRun(remaining_enum_cmds)

    def getOpenPorts():
        np = nmapParser.NmapParserFunk(args.target)
        np.openPorts()

    def scanTop10000Ports():
        ntp = topOpenPorts.TopOpenPorts(args.target)
        ntp.Scan()

    def fullTcpAndTopUdpScan():
        ntp = topOpenPorts.TopOpenPorts(args.target)
        ntp.topUdpAllTcp()
        nmap_commands = ntp.processes
        mpRun(nmap_commands)

    def aquatone():
        aq = aqua.Aquatone(args.target)
        aq.Scan()

    def peace():
        pe = peaceout_banner.PeaceOut()
        pe.bannerOut()

    def cmsEnum():
        cm = enumWeb.EnumWeb(args.target)
        cm.CMS()
        cms_commands = cm.cms_processes
        mpRun(cms_commands)

    def cmsEnumSSL():
        cms = enumWebSSL.EnumWebSSL(args.target)
        cms.sslEnumCMS()
        cms_ssl_commands = cms.cms_processes
        mpRun(cms_ssl_commands)

    def proxyEnum():
        pscan = enumProxy.CheckProxy(args.target)
        pscan.Scan()
        pr = nmapParser.NmapParserFunk(args.target)
        pr.openProxyPorts()
        pscan.Enum()
        proxy_commands = pscan.all_processes
        mpRun(proxy_commands)

    def proxyEnumCMS():
        pcms = enumProxyCMS.EnumProxyCMS(args.target)
        pcms.proxyCMS()
        proxy_cms_commands = pcms.cms_processes
        mpRun(proxy_cms_commands)

    def enumLdap():
        ld = ldapEnum.LdapEnum(args.target)
        ld.Scan()
        ldap_cmds = ld.processes
        mpRun(ldap_cmds)
        ld.ldapSearch()

    def enumOracle():
        oc = oracleEnum.OracleEnum(args.target)
        oc.Scan()
        oracle_cmds = oc.processes
        mpRun(oracle_cmds)
        oc.OraclePwn()

    def getUdpPorts():
        udp = nmapParser.NmapParserFunk(args.target)
        udp.openUdpPorts()

    def sshUserBrute():
        sb = brute.Brute(args.target, args.brute, args.port)
        sb.SshUsersBrute()

    def sshSingleUserBrute():
        sb = brute.BruteSingleUser(args.target, args.brute, args.port, args.user)
        sb.SshSingleUserBrute()

    def sshSingleUserBruteCustom():
        sb = brute.BruteSingleUserCustom(
            args.target, args.brute, args.port, args.user, args.PASSWORDS
        )
        sb.SshSingleUserBruteCustom()

    def searchSploits():
        ss = searchsploits.Search(args.target)
        ss.Scan()
        ss.vulnCheck()

    def sortFoundUrls():
        ds = helper_lists.DirsearchURLS(args.target)
        ds.genDirsearchUrlList()

    def sortFoundProxyUrls():
        ds = helper_lists.DirsearchURLS(args.target)
        ds.genProxyDirsearchUrlList()

    # This is the Full Scan option for a Single Target
    if (
        args.target
        and (args.file is None)
        and (args.brute is None)
        and (args.port is None)
        and (args.user is None)
        and (args.USERS is None)
        and (args.PASSWORDS is None)
    ):
        validateIP()
        scanTop10000Ports()
        getOpenPorts()  # Must Always be ON
        enumDNS()
        enumHTTP()
        cmsEnum()
        enumHTTPS()
        cmsEnumSSL()
        sortFoundUrls()
        proxyEnum()
        sortFoundProxyUrls()
        proxyEnumCMS()
        aquatone()
        enumSMB()
        enumLdap()
        enumOracle()
        fullTcpAndTopUdpScan()
        getUdpPorts()
        enumRemainingServices()
        searchSploits()
        removeColor()
        peace()
    # This is for the -f --file Option and will run all scans on all IP addresses
    # In the provided file. Should be 1 IPv4 address per line
    elif (
        args.file
        and (args.target is None)
        and (args.brute is None)
        and (args.port is None)
        and (args.user is None)
        and (args.USERS is None)
        and (args.PASSWORDS is None)
    ):
        try:
            with open(args.file, "r") as ips:
                for ip in ips:
                    args.target = ip.rstrip()
                    validateIP()
                    scanTop10000Ports()
                    getOpenPorts()  # Must Always be ON
                    enumDNS()
                    enumHTTP()
                    cmsEnum()
                    enumHTTPS()
                    cmsEnumSSL()
                    getProxyPorts()
                    proxyEnum()
                    enumSMB()
                    enumLdap()
                    enumOracle()
                    fullTcpAndTopUdpScan()
                    getUdpPorts()
                    enumRemainingServices()
                    searchSploits()
                    removeColor()
                    aquatone()
                    peace()
        except FileNotFoundError as fnf_error:
            print(fnf_error)
            exit()
    # This is for the -w --web opton and will run all Web Enumeration on a single target
    # The -t --target argument is required.
    elif (
        args.web
        and (args.target is None)
        and (args.port is None)
        and (args.user is None)
        and (args.USERS is None)
        and (args.PASSWORDS is None)
        and (args.file is None)
    ):
        args.target = args.web
        validateIP()
        if os.path.exists(f"{args.target}-Report/nmap/top-ports-{args.target}.nmap"):
            getOpenPorts()
            enumDNS()
            enumHTTP2()
            cmsEnum()
            enumHTTPS2()
            cmsEnumSSL()
            removeColor()
            aquatone()
            peace()
        else:
            scanTop10000Ports()
            getOpenPorts()
            enumDNS()
            enumHTTP2()
            cmsEnum()
            enumHTTPS2()
            cmsEnumSSL()
            removeColor()
            aquatone()
            peace()

    # This is the Brute forcing option and -t --target argument is required
    elif args.target and (args.file is None) and args.brute:
        if "ssh" in args.brute:
            if args.port is None:
                args.port = "22"
                if args.user is None and (args.PASSWORDS is None) and (args.USERS is None):
                    print(
                        f"{teal}Brute Forcing SSH usernames with wordlist: {cwd}/wordlists/usernames.txt on default SSH port,{reset} {args.port}"
                    )
                    if os.path.exists(f"{args.target}-Report/nmap/top-ports-{args.target}.nmap"):
                        sshUserBrute()
                    else:
                        scanTop10000Ports()
                        sshUserBrute()
                elif args.user is None and args.USERS:
                    print(f"Brute Forcing Usernames with userlist {args.USERS}")
                elif args.user and (args.PASSWORDS is None):
                    print(f"Brute Forcing {args.user}'s password with default wordlist")
                    sshSingleUserBrute()
                elif args.user and args.PASSWORDS:
                    print(
                        f"Brute Forcing username, {args.user} with password list, {args.PASSWORDS}"
                    )
                    sshSingleUserBruteCustom()
                elif args.USERS and (args.PASSWORDS is None):
                    print(
                        f"Brute Forcing SSH with username list, {args.USERS} and default password list"
                    )
                elif args.USERS and args.PASSWORDS:
                    print(
                        f"Brute Forcing SSH with username list, {args.USERS} and password list, {args.PASSWORDS}"
                    )
                else:
                    print(EXAMPLES)
            else:
                if args.user is None and (args.PASSWORDS is None) and (args.USERS is None):
                    print(f"{teal}Brute Forcing SSH usernames on port,{reset} {args.port}")
                    if os.path.exists(f"{args.target}-Report/nmap/top-ports-{args.target}.nmap"):
                        sshUserBrute()
                    else:
                        scanTop10000Ports()
                        sshUserBrute()
                elif args.user and (args.PASSWORDS is None):
                    print(
                        f"Brute Forcing {args.user}'s password with default wordlist on port, {args.port}"
                    )
                    sshSingleUserBrute()
                elif args.user and args.PASSWORDS:
                    print(
                        f"Brute Forcing username, {args.user} with password list, {args.PASSWORDS} on port, {args.port}"
                    )
                    sshSingleUserBruteCustom()
                elif args.USERS and (args.PASSWORDS is None):
                    print(
                        f"Brute Forcing SSH with username list, {args.USERS} and default password list on port, {args.port}"
                    )
                elif args.USERS and args.PASSWORDS:
                    print(
                        f"Brute Forcing SSH with username list, {args.USERS} and password list, {args.PASSWORDS} on port, {args.port}"
                    )
                else:
                    print(EXAMPLES)
        elif "smb" in args.brute:
            if args.port is None:
                args.port = "445"
                print("ToDo: Impliment SMB brute forcing")
            else:
                print("ToDo: Impliment SMB brute forcing")
                # print(f"Brute Forcing SMB on port {args.port}")
        elif "ftp" in args.brute:
            if args.port is None:
                args.port = "21"
                print("ToDo: Impliment FTP brute forcing")
                # print("Brute Forcing FTP USERS on default port 21")
            else:
                print("ToDo: Impliment FTP brute forcing")
                # print(f"Brute Forcing FTP on port {args.port}")
        elif "http" in args.brute:
            if args.port is None:
                args.port = "80"
                print("ToDo: Impliment http brute forcing")
            else:
                # print(f"Brute Forcing http on port {args.port}")
                print("ToDo: Impliment http brute forcing")

    elif args.file and args.target:
        print(f"{bad_cmd} Cannot use -t {args.target} and -f {args.file} together")
        print(EXAMPLES)
        parser.print_help(sys.stderr)
    else:
        print(EXAMPLES)
        parser.print_help(sys.stderr)

    end = time.time()
    time_elapsed = end - startTimer
    durationMSG = fg.cyan + f"All Scans Completed for {args.target} in: " + fg.rs
    print(durationMSG, display_time(time_elapsed))


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    main()
