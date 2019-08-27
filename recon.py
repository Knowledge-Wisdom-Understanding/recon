#!/usr/bin/env python3

from lib import topOpenPorts
from lib import nmapOpenPorts
from lib import nmapParser
from lib import enumWeb
from lib import enumWebSSL
from lib import smbEnum
from lib import dnsenum
from utils import remove_color
from termcolor import colored
from sty import fg, bg, ef, rs, RgbFg
import colorama
from colorama import Fore, Back, Style
import argparse
import time
import sys
import random
import os
import shutil
from subprocess import call
from multiprocessing import Pool
from functools import partial
import socket

colorama.init()

green_plus = fg.li_green + "+" + fg.rs
cmd_info = "[" + green_plus + "]"

intervals = (
    ("weeks", 604800),  # 60 * 60 * 24 * 7
    ("days", 86400),  # 60 * 60 * 24
    ("hours", 3600),  # 60 * 60
    ("minutes", 60),
    ("seconds", 1),
)


def banner():
    def random_color():
        valid_colors = ("red", "green", "yellow", "blue", "magenta", "cyan")
        return random.choice(valid_colors)

    def random_freight():
        valid_frieghts = (
            """
                           #########                      
                        ######                            
                   ___###___________                      
            _,--'''_________________'''--._               
          /',--'\\"##           __  "//'--.'\   ,  /\    _
-._  /\  //'   ##\\       ,-_,-'  \_///\,-'`\\-' \/  \,-' 
   \/  \//    _  _\\ ,-._/         //'       \\           
       //'--._ _| |\\___   ___   _//   ___   _\\   ___    
      | |    (|   | \\  | | Y | |// | | E | | | | | S |   
   ___| |   /ooo=oo-o\\oo-oo=oo-//=oo-oo=oo-oo| |=oo=oo___
        \"'"'"'"'"'"'"'"'"'"'"'"'"'"'"'"'"'"'"|           
         |    \                           .   /           
   .      \   /\            .  -     '    .  /            
           `-.  '-..     ' '          ,  ,,-'     `       
              \     '- '            ,/,-'/                
    \          \_- ' '             --',-'                 
              -'                    \/            |       
     |  _  -                          - _        .       
                                                /                  
    o o o o o o o . . .   ______________________________ _____=======_||____
   o      _____           ||                            | |                 |
 .][__n_n_|DD[  ====_____  |    Yes         Knotez      | |   Loaf   Dems   |
>(________|__|_[_________]_|____________________________|_|_________________|
_/oo OOOOO oo`  ooo   ooo  'o!o!o                  o!o!o` 'o!o         o!o`
-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
                    """,
            """
       _____________          ____    ________________                               
      /___/___      \        /  / |  /___/__          \                   _____      
          /  /   _   \______/__/  |______|__|_____ *   \_________________/__/  |___  
       __/__/   /_\   \ |  |  \   __\/  _ \|  |       __/ __ \_/ ___\/  _ \|       | 
      |   |     ___    \|  |  /|  | (  |_| )  |    |   \  ___/\  \__(  |_| )   |   | 
      |___|____/\__\____|____/_|__|\_\____/|__|____|_  /\___  |\___  \____/|___|  /  
                                                 \___\/  \__\/  \___\/      \___\/   
                 gtihub.com/Knowledge-Wisdom-Understanding
""",
        )
        return random.choice(valid_frieghts)

    def print_art(msg, color):
        colored_art = colored(msg, color=color)
        print(colored_art)

    freight = random_freight()
    color = random_color()
    print_art(freight, color)


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


def main():
    banner()
    startTimer = time.time()
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", help="Single IPv4 Target to Scan")

    args = parser.parse_args()

    def validateIP():
        red = "[" + fg.red + "+" + fg.rs + "]"
        try:
            s = socket.inet_aton(args.target)
        except socket.error:
            print("")
            print(f"{red} Bad IP address")
            print("")
            sys.exit()

    def removeColor():
        nocolor = remove_color.Clean(args.target)
        nocolor.listfiles()

    def getOpenPorts():
        p = topOpenPorts.TopOpenPorts(args.target)
        p.Scan()

    def enumHTTP():
        eweb = enumWeb.EnumWeb(args.target)
        eweb.Scan()
        web_enum_commands = eweb.processes
        for command in web_enum_commands:
            print(cmd_info, command)
        pool = Pool(2)
        for i, returncode in enumerate(
            pool.imap(partial(call, shell=True), web_enum_commands)
        ):
            if returncode != 0:
                print(f"{i} command failed: {returncode}")

    def enumHTTPS():
        webssl = enumWebSSL.EnumWebSSL(args.target)
        webssl.Scan()
        web_ssl_enum_commands = webssl.processes
        for command in web_ssl_enum_commands:
            print(cmd_info, command)
        pool2 = Pool(2)  # Run 2 concurrent commands at a time
        for i, returncode in enumerate(
            pool2.imap(partial(call, shell=True), web_ssl_enum_commands)
        ):
            if returncode != 0:
                pprint(f"{i} command failed: {returncode}")

    def enumDNS():
        dn = dnsenum.DnsEnum(args.target)
        dn.Scan()
        dns_enum_commands = dn.processes
        for command in dns_enum_commands:
            print(cmd_info, command)
        pool4 = Pool(2)
        for i, returncode in enumerate(
            pool4.imap(partial(call, shell=True), dns_enum_commands)
        ):
            if returncode != 0:
                print(f"{i} command failed: {returncode}")

    def enumSMB():
        smb = smbEnum.SmbEnum(args.target)
        smb.Scan()
        smb_enum_commands = smb.processes
        for command in smb_enum_commands:
            print(cmd_info, command)
        pool3 = Pool(2)  # Run 2 concurrent commands at a time
        for i, returncode in enumerate(
            pool3.imap(partial(call, shell=True), smb_enum_commands)
        ):
            if returncode != 0:
                print(f"{i} command failed: {returncode}")

    def enumTopTcpPorts():
        g = fg.cyan + "Running Nmap Default Scripts on all open TCP Ports:" + fg.rs
        print(g)
        nmapTCP = nmapOpenPorts.NmapOpenPorts(args.target)
        nmapTCP.Scan()

    def getOpenPorts():
        np = nmapParser.NmapParserFunk(args.target)
        np.openPorts()

    def scanTop10000Ports():
        ntp = topOpenPorts.TopOpenPorts(args.target)
        ntp.Scan()

    def fullTcpScan():
        ntp = topOpenPorts.TopOpenPorts(args.target)
        ntp.fullScan()

    if args.target:
        validateIP()
        scanTop10000Ports()
        getOpenPorts()  # Must Always be ON
        enumTopTcpPorts()
        enumDNS()
        enumHTTP()
        enumHTTPS()
        enumSMB()
        fullTcpScan()
        removeColor()

    else:
        print("Must supply a target see help message")

    end = time.time()
    time_elapsed = end - startTimer
    durationMSG = fg.cyan + "All Scans Completed in: " + fg.rs
    print(durationMSG, display_time(time_elapsed))


if __name__ == "__main__":
    main()
