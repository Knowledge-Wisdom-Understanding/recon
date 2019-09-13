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
        np.allOpenPorts()
        ftpPorts = np.ftp_ports
        smtpPorts = np.smtp_ports
        nfsPorts = np.nfs_ports
        rpcPorts = np.rpc_ports
        telnetPorts = np.telnet_ports
        sipPorts = np.sip_ports
        vncPorts = np.vnc_ports
        cupsPorts = np.cups_ports
        javaRmiPorts = np.java_rmi_ports
        mssqlPorts = np.mssql_ports
        mysqlPorts = np.mysql_ports
        cassandraPorts = np.cassandra_ports
        mongoPorts = np.mongo_ports
        pop3Ports = np.pop3_ports
        kerberosPorts = np.kerberos_ports
        unp = nmapParser.NmapParserFunk(self.target)
        unp.openUdpPorts()
        snmpPorts = unp.snmp_ports
        sipUdpPorts = unp.sip_udp_ports
        cwd = os.getcwd()
        reportDir = f"{cwd}/{self.target}-Report"
        unsorted_commands = []
        if len(snmpPorts) != 0:
            if not os.path.exists(f"{reportDir}/snmp"):
                os.makedirs(f"{reportDir}/snmp")
            snmp_walk_cmd = (
                f"snmpwalk -c public -v2c {self.target} | tee {reportDir}/snmp/snmpwalk.log"
            )
            snmp_check_cmd = (
                f"snmp-check -c public -v 1 -d {self.target} | tee {reportDir}/snmp/snmp-check.log"
            )
            onesixty_one_cmd = f"onesixtyone -c /usr/share/doc/onesixtyone/dict.txt {self.target} | tee {reportDir}/snmp/onesixtyone.log"
            unsorted_commands.append(snmp_check_cmd)
            unsorted_commands.append(snmp_walk_cmd)
            unsorted_commands.append(onesixty_one_cmd)
        if len(ftpPorts) != 0:
            string_ftp_ports = ",".join(map(str, ftpPorts))
            ftp_enum_cmd = f"nmap -vv -sV -Pn -p {string_ftp_ports} --script=ftp-anon.nse,ftp-bounce.nse,ftp-libopie.nse,ftp-proftpd-backdoor.nse,ftp-vsftpd-backdoor.nse,ftp-vuln-cve2010-4221.nse,ftp-syst.nse -v -oA {reportDir}/nmap/ftp-enum {self.target}"
            unsorted_commands.append(ftp_enum_cmd)
        if len(smtpPorts) != 0:
            if not os.path.exists(f"{reportDir}/smtp"):
                os.makedirs(f"{reportDir}/smtp")
            for p in smtpPorts:
                smtp_cmd = f"smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t {self.target} -p {p} 2>&1 | tee {reportDir}/smtp/smtp-user-enum-port-{p}.log"
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
        if len(sipPorts) != 0:
            if not os.path.exists(f"{reportDir}/sip"):
                os.makedirs(f"{reportDir}/sip")
            string_sip_ports = ",".join(map(str, sipPorts))
            sip_nmap_cmd = f"nmap -sV -p {string_sip_ports} --script='banner,sip-enum-users,sip-methods' -oA {reportDir}/nmap/sip {self.target}"
            sip_svwar_cmd2 = (
                f"svwar -D -m INVITE {self.target} 2>&1 | tee {reportDir}/sip/svwar.txt"
            )
            unsorted_commands.append(sip_nmap_cmd)
            unsorted_commands.append(sip_svwar_cmd2)
        if len(vncPorts) != 0:
            string_vnc_ports = ",".join(map(str, vncPorts))
            vnc_nmap_cmd = f"nmap -Pn -sV -p {string_vnc_ports} --script='banner,(vnc* or realvnc* or ssl*) and not (brute or broadcast or dos or external or fuzzer) --script-args='unsafe=1' -oA {reportDir}/nmap/vnc {self.target}"
            unsorted_commands.append(vnc_nmap_cmd)
        if len(telnetPorts) != 0:
            string_telnet_ports = ",".join(map(str, telnetPorts))
            telnet_nmap_cmd = f"nmap -Pn -sV -p {string_telnet_ports} --script='banner,telnet-encryption,telnet-ntlm-info' -oA {reportDir}/nmap/telnet {self.target}"
            unsorted_commands.append(telnet_nmap_cmd)
        if len(cassandraPorts) != 0:
            string_cassandra_ports = ",".join(map(str, cassandraPorts))
            cassandra_nmap_cmd = f"""nmap -Pn -sV -p {string_cassandra_ports} --script="banner,(cassandra* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oA {reportDir}/nmap/cassandra {self.target}"""
            unsorted_commands.append(cassandra_nmap_cmd)
        if len(mssqlPorts) != 0:
            string_mssql_ports = ",".join(map(str, mssqlPorts))
            mssql_nmap_cmd = f"""nmap -Pn -sV -p {string_mssql_ports} --script="banner,(ms-sql* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --script-args="mssql.instance-port={mssqlPorts[0]},mssql.username=sa,mssql.password=sa" -oA {reportDir}/nmap/mssql {self.target}"""
            unsorted_commands.append(mssql_nmap_cmd)
        if len(mysqlPorts) != 0:
            string_mysql_ports = ",".join(map(str, mysqlPorts))
            mysql_nmap_cmd = f"""nmap -Pn -sV -p {string_mysql_ports} --script="banner,(mysql* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oA {reportDir}/nmap/mysql {self.target}"""
            unsorted_commands.append(mysql_nmap_cmd)
        if len(mongoPorts) != 0:
            string_mongo_ports = ",".join(map(str, mongoPorts))
            mongo_nmap_cmd = f"""nmap -Pn -sV -p {string_mongo_ports} --script="banner,(mongodb* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oA {reportDir}/nmap/mongo {self.target}"""
            unsorted_commands.append(mongo_nmap_cmd)
        if len(pop3Ports) != 0:
            string_pop3_ports = ",".join(map(str, pop3Ports))
            pop3_nmap_cmd = f"""nmap -Pn -sV -p {string_pop3_ports} --script="banner,(pop3* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oA {reportDir}/nmap/pop3 {self.target}"""
            unsorted_commands.append(pop3_nmap_cmd)
        if len(kerberosPorts) != 0:
            string_kerberos_ports = ",".join(map(str, kerberosPorts))
            kerberos_nmap_cmd = f"""nmap -Pn -sV -p {string_kerberos_ports} --script="banner,krb5-enum-users" -oA {reportDir}/nmap/kerberos {self.target}"""
            unsorted_commands.append(kerberos_nmap_cmd)

        set_sorted_cmds = sorted(set(unsorted_commands))
        cmds_to_run = []
        for i in set_sorted_cmds:
            cmds_to_run.append(i)
        mpCmds = tuple(cmds_to_run)
        self.processes = mpCmds

