#!/usr/bin/env python3

import os
from lib import nmapParser
from shutil import which


class NmapOpenPorts:
    def __init__(self, target):
        self.target = target
        self.processes = ""

    def Scan(self):
        cwd = os.getcwd()
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        ftpPorts = np.ftp_ports
        smtpPorts = np.smtp_ports
        nfsPorts = np.nfs_ports
        rpcPorts = np.rpc_ports
        cupsPorts = np.cups_ports
        javaRmiPorts = np.java_rmi_ports
        unp = nmapParser.NmapParserFunk(self.target)
        unp.openUdpPorts()
        snmpPorts = unp.snmp_ports
        cwd = os.getcwd()
        reportDir = f"{cwd}/{self.target}-Report"
        unsorted_commands = []
        if len(snmpPorts) != 0:
            snmp_walk_cmd = f"snmpwalk -c public -v2c {self.target} | tee {reportDir}/snmpwalk.log"
            snmp_check_cmd = (
                f"snmp-check -c public -v 1 -d {self.target} | tee {reportDir}/snmp-check.log"
            )
            onesixty_one_cmd = f"onesixtyone -c /usr/share/doc/onesixtyone/dict.txt {self.target} | tee {reportDir}/onesixtyone.log"
            if not os.path.exists(f"{reportDir}/snmp"):
                os.makedirs(f"{reportDir}/snmp")
            unsorted_commands.append(snmp_check_cmd)
            unsorted_commands.append(snmp_walk_cmd)
            unsorted_commands.append(onesixty_one_cmd)
        if len(ftpPorts) != 0:
            string_ftp_ports = ",".join(map(str, ftpPorts))
            ftp_enum_cmd = f"nmap -vv -sV -Pn -p {string_ftp_ports} --script=ftp-anon.nse,ftp-bounce.nse,ftp-libopie.nse,ftp-proftpd-backdoor.nse,ftp-vsftpd-backdoor.nse,ftp-vuln-cve2010-4221.nse,ftp-syst.nse -v -oA {reportDir}/nmap/ftp-enum {self.target}"
            unsorted_commands.append(ftp_enum_cmd)
        if len(smtpPorts) != 0:
            for p in smtpPorts:
                smtp_cmd = f"smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t {self.target} -p {p} 2>&1 | tee {reportDir}/smtp-user-enum-port-{p}.log"
                unsorted_commands.append(smtp_cmd)
        if len(nfsPorts) != 0:
            if not os.path.exists(f"{reportDir}/nfs"):
                os.makedirs(f"{reportDir}/nfs")
            string_nfs_ports = ",".join(map(str, nfsPorts))
            nfs_cmd = f"nmap -vv -sV -p {string_nfs_ports} --script=nfs-ls.nse,nfs-statfs.nse,nfs-showmount.nse -oA {reportDir}/nmap/nfs {self.target}"
            nfs_cmd_2 = f"showmount -e {self.target} 2>&1 | tee {reportDir}/nfs/nfs-show-mount.txt"
            unsorted_commands.append(nfs_cmd)
            unsorted_commands.append(nfs_cmd_2)
        if len(rpcPorts) != 0:
            if not os.path.exists(f"{reportDir}/rpc"):
                os.makedirs(f"{reportDir}/rpc")
            rpc_cmds = f"enum4linux -av {self.target} | tee {reportDir}/rpc/rpc-enum4linux.log"
            unsorted_commands.append(rpc_cmds)
            if which("impacket-rpcdump"):
                rpc_cmd_2 = f"impacket-rpcdump @{self.target}"
                unsorted_commands.append(rpc_cmd_2)
        if len(cupsPorts) != 0:
            string_cups_ports = ",".join(map(str, cupsPorts))
            cups_cmd = f"nmap -vv -sV -Pn --script=cups-info.nse,cups-queue-info.nse -p {string_cups_ports} -oA {reportDir}/nmap/cups-enum {self.target}"
            unsorted_commands.append(cups_cmd)
        if len(javaRmiPorts) != 0:
            string_java_rmi_ports = ",".join(map(str, javaRmiPorts))
            javaRmi_cmd = f"nmap -vv -sV -Pn --script=rmi-vuln-classloader.nse -p {string_java_rmi_ports} -oA {reportDir}/nmap/java-rmi {self.target}"
            javaRmi_cmd2 = f"nmap -vv -sV -Pn --script=rmi-dumpregistry.nse -p {string_java_rmi_ports} -oA {reportDir}/nmap/java-rmi {self.target}"
            unsorted_commands.append(javaRmi_cmd)
            unsorted_commands.append(javaRmi_cmd2)

        set_sorted_cmds = sorted(set(unsorted_commands))
        cmds_to_run = []
        for i in set_sorted_cmds:
            cmds_to_run.append(i)
        mpCmds = tuple(cmds_to_run)
        self.processes = mpCmds

