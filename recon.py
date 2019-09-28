#!/usr/bin/env python3

from termcolor import colored
from lib import brute
from sty import fg, bg, ef, rs
import argparse
import signal
import time
import sys
import random
import os
import socket
from utils import run_commands

bad_cmd = "[" + fg.li_red + "+" + fg.rs + "]"
green = fg.li_green
teal = fg.li_cyan
purp = fg.li_magenta
yellow = fg.li_yellow
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
    """Print the AutoRecon Banner."""

    def random_color():
        valid_colors = ("red", "green", "yellow", "blue", "magenta", "cyan")
        return random.choice(valid_colors)

    autoRecon = r"""
       _____________          ____    ________________
      /___/___      \        /  / |  /___/__          \                   _____
          /  /   _   \______/__/  |______|__|_____ *   \_________________/__/  |___
       __/__/   /_\   \ |  |  \   __\/  _ \|  |       __/ __ \_/ ___\/  _ \|       |
      |   |     ___    \|  |  /|  | (  |_| )  |    |   \  ___/\  \__(  |_| )   |   |
      |___|____/\__\____|____/_|__|\_\____/|__|____|_  /\___  |\___  \____/|___|  /
      gtihub.com/Knowledge-Wisdom-Understanding  \___\/  \__\/  \__\_/ v3.1 \___\/

"""

    def print_art(msg, color):
        colored_art = colored(msg, color=color)
        print(colored_art)

    color = random_color()
    print_art(autoRecon, color)


def display_time(seconds, granularity=2):
    """Helper function for the timer that is displayed at the Scans Completion."""
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


VERSION = 3.1


def main():
    """Call All the Functionlity from all lib files to automate the enumeration process."""
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
        "-U",
        "--USERS",
        help="List of usernames to try for brute forcing. Not yet implimented",
    )
    parser.add_argument(
        "-P", "--PASSWORDS", help="List of passwords to try. Not required for SSH"
    )

    args = parser.parse_args()

    target_time = []

    def reset_timer():
        """Reset the timer which is most useful when scanning a list of hosts from a file."""
        resetTimer = time.time()
        target_time.clear()
        target_time.append(resetTimer)

    def check_timer():
        """Check the current timer output. Most useful when the -f argument is supplied from the CLI."""
        end = time.time()
        time_elapsed = end - target_time[0]
        durationMSG = fg.cyan + f"Scans Completed for {args.target} in: " + fg.rs
        print(durationMSG, display_time(time_elapsed))

    def validateIP():
        """Validate the target IP Before running the tools."""
        try:
            s = socket.inet_aton(args.target)
        except socket.error:
            print("")
            print(f"{bad_cmd} Bad IP address")
            print("")
            sys.exit()

    def sshUserBrute():
        """Helper Function to Call the SSHBRUTE option / Class"""
        sb = brute.Brute(args.target, args.brute, args.port)
        sb.SshUsersBrute()

    def sshSingleUserBrute():
        """Helper Function to Call the SSHBRUTE option / Class for a single specified username."""
        sb = brute.BruteSingleUser(args.target, args.brute, args.port, args.user)
        sb.SshSingleUserBrute()

    def sshSingleUserBruteCustom():
        """Helper Function to Call the SSHBRUTE option / Class for a single specified username With a custom PasswordList."""
        sb = brute.BruteSingleUserCustom(args.target, args.brute, args.port, args.user, args.PASSWORDS)
        sb.SshSingleUserBruteCustom()

    def sshMultipleUsersBruteCustom():
        """Helper Function to Call the SSHBRUTE option / Class for a single specified username With a custom PasswordList."""
        sb = brute.BruteMultipleUsersCustom(args.target, args.brute, args.port, args.USERS, args.PASSWORDS)
        sb.SshMultipleUsersBruteCustom()

    rc = run_commands.RunCommands(args.target)

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
        reset_timer()
        rc.scanTopTcpPorts()
        rc.enumDNS()
        rc.enumHTTP()
        rc.cmsEnum()
        rc.enumHTTPS()
        rc.cmsEnumSSL()
        rc.sortFoundUrls()
        rc.proxyEnum()
        rc.sortFoundProxyUrls()
        rc.proxyEnumCMS()
        rc.aquatone()
        rc.checkSource()
        rc.enumSMB()
        rc.enumLdap()
        rc.removeColor()
        rc.enumOracle()
        rc.fullTcpAndTopUdpScan()
        rc.enumRemainingServices()
        rc.searchSploits()
        rc.removeColor()
        rc.peace()
        check_timer()
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
                    reset_timer()
                    rc.scanTopTcpPorts()
                    rc.enumDNS()
                    rc.enumHTTP()
                    rc.cmsEnum()
                    rc.enumHTTPS()
                    rc.cmsEnumSSL()
                    rc.sortFoundUrls()
                    rc.proxyEnum()
                    rc.sortFoundProxyUrls()
                    rc.proxyEnumCMS()
                    rc.aquatone()
                    rc.checkSource()
                    rc.enumSMB()
                    rc.enumLdap()
                    rc.removeColor()
                    rc.enumOracle()
                    rc.fullTcpAndTopUdpScan()
                    rc.enumRemainingServices()
                    rc.searchSploits()
                    rc.removeColor()
                    rc.peace()
                    check_timer()
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
            reset_timer()
            rc.enumDNS()
            rc.enumHTTP2()
            rc.cmsEnum()
            rc.enumHTTPS2()
            rc.cmsEnumSSL()
            rc.removeColor()
            rc.aquatone()
            rc.checkSource()
            rc.peace()
            check_timer()
        else:
            reset_timer()
            rc.scanTopTcpPorts()
            rc.enumDNS()
            rc.enumHTTP2()
            rc.cmsEnum()
            rc.enumHTTPS2()
            rc.cmsEnumSSL()
            rc.removeColor()
            rc.aquatone()
            rc.checkSource()
            rc.peace()
            check_timer()

    # This is the Brute forcing option and -t --target argument is required
    elif args.target and (args.file is None) and args.brute:
        if "ssh" in args.brute:
            if args.port is None:
                args.port = "22"
                if (
                    args.user is None
                    and (args.PASSWORDS is None)
                    and (args.USERS is None)
                ):
                    print(f"{teal}Brute Forcing SSH usernames with wordlist: {cwd}/wordlists/usernames.txt on default SSH port,{reset} {args.port}")
                    if os.path.exists(f"{args.target}-Report/nmap/top-ports-{args.target}.nmap"):
                        sshUserBrute()
                    else:
                        rc.scanTopTcpPorts()
                        sshUserBrute()
                elif args.user is None and args.USERS:
                    print(f"Brute Forcing Usernames with userlist {args.USERS}")
                elif args.user and (args.PASSWORDS is None):
                    print(f"Brute Forcing {args.user}'s password with default wordlist")
                    sshSingleUserBrute()
                elif args.user and args.PASSWORDS:
                    print(f"Brute Forcing username, {args.user} with password list, {args.PASSWORDS}")
                    sshSingleUserBruteCustom()
                elif args.USERS and (args.PASSWORDS is None):
                    print(f"Brute Forcing SSH with username list, {args.USERS} and default password list")
                elif args.USERS and args.PASSWORDS:
                    print(f"Brute Forcing SSH with username list, {args.USERS} and password list, {args.PASSWORDS}")
                else:
                    print(EXAMPLES)
            else:
                if (
                    args.user is None
                    and (args.PASSWORDS is None)
                    and (args.USERS is None)
                ):
                    print(f"{teal}Brute Forcing SSH usernames on port,{reset} {args.port}")
                    if os.path.exists(f"{args.target}-Report/nmap/top-ports-{args.target}.nmap"):
                        sshUserBrute()
                    else:
                        rc.scanTopTcpPorts()
                        sshUserBrute()
                elif args.user and (args.PASSWORDS is None):
                    print(f"Brute Forcing {args.user}'s password with default wordlist on port, {args.port}")
                    sshSingleUserBrute()
                elif args.user and args.PASSWORDS:
                    print(f"Brute Forcing username, {args.user} with password list, {args.PASSWORDS} on port, {args.port}")
                    sshSingleUserBruteCustom()
                elif args.USERS and (args.PASSWORDS is None):
                    print(f"Brute Forcing SSH with username list, {args.USERS} and default password list on port, {args.port}")
                elif args.USERS and args.PASSWORDS:
                    print(f"Brute Forcing SSH with username list, {args.USERS} and password list, {args.PASSWORDS} on port, {args.port}")
                    sshMultipleUsersBruteCustom()
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
    durationMSG = fg.cyan + f"All Scans Completed in: " + fg.rs
    print(durationMSG, display_time(time_elapsed))


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    main()
