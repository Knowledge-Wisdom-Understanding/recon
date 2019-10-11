#!/usr/bin/env python3

from subprocess import call
from tqdm import tqdm
from multiprocessing import Pool
from functools import partial
from lib import enumWeb
from lib import enumWebSSL
from utils import config_parser
import psutil
from sty import fg
import os
import signal
import logging


class RunWebCommands:
    """Helper Class to Wrap all commands in easy to access functions that can be called easily."""

    def __init__(self, target, web):
        self.target = target
        self.web = web
        # self.run_commands_parent_pid = os.getpid()

    def loginator(self, executed_command):
        c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
        logging.basicConfig(
            filename=c.getPath("report", "log"),
            format='%(asctime)s %(message)s',
            datefmt='%m/%d/%Y %I:%M:%S %p',
            level=logging.INFO
        )
        logging.info(f"[+] {executed_command}")

    def mpRun(self, commands):
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
                            pbar.write(f"[{green}+{reset}] {green}{commands[i]}{reset}")
                            pbar.set_description_str(desc=f"{fg.li_yellow}{commands[i].split()[:1]}{fg.rs}")
                            self.loginator(commands[i])
                            if returncode != 0:
                                print(f"{i} command failed: {returncode}")
                except KeyboardInterrupt:
                    p.close()
                    p.terminate()
                    p.join()

    def enumHTTP2(self):
        """Helper function to call the lib/enumWeb Large Wordlists Class."""
        eweb = enumWeb.EnumWeb2(self.web, self.target)
        eweb.ScanWebOption()
        web_enum_commands = eweb.processes
        self.mpRun(web_enum_commands)

    def enumHTTPS2(self):
        """Helper function to call the lib/enumWebSSL Large Wordlists Class."""
        webssl = enumWebSSL.EnumWebSSL2(self.web, self.target)
        webssl.ScanWebOption()
        web_ssl_enum_commands = webssl.processes
        self.mpRun(web_ssl_enum_commands)
