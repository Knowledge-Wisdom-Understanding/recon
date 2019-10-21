#!/usr/bin/env python3

import os
from lib import nmapParser
from shutil import which
from utils import config_parser
from heapq import merge


class NmapOpenPorts:
    """NmapOpenPorts will enumerate all remaining found open ports services that were discovered from the
    fullTcp and Top UDP nmap scan results."""

    def __init__(self, target):
        self.target = target
        self.processes = ""

    def Scan(self):
        """This Scan Function will proceed to enumerate all the remaining services
        found by nmaps fullTcpScan results. The following services will be enumerated
        if their respective ports are open. FTP, SMTP, NFS, RPC, TELNET, SIP, VNC, CUPS, MSSQL,
        MYSQL, CASSANDRA, MONGODB, POP3 SNMP, AND KERBEROS."""
        ntop = nmapParser.NmapParserFunk(self.target)
        ntop.openPorts()
        np = nmapParser.NmapParserFunk(self.target)
        np.allOpenPorts()
        ftpPorts = list(sorted(set(merge(np.ftp_ports, ntop.ftp_ports))))
        smtpPorts = list(sorted(set(merge(ntop.smtp_ports, np.smtp_ports))))
        nfsPorts = list(sorted(set(merge(ntop.nfs_ports, np.nfs_ports))))
        rpcPorts = list(sorted(set(merge(ntop.rpc_ports, np.rpc_ports))))
        telnetPorts = list(sorted(set(merge(ntop.telnet_ports, np.telnet_ports))))
        sipPorts = list(sorted(set(merge(ntop.sip_ports, np.sip_ports))))
        vncPorts = list(sorted(set(merge(ntop.vnc_ports, np.vnc_ports))))
        cupsPorts = list(sorted(set(merge(ntop.cups_ports, np.cups_ports))))
        javaRmiPorts = list(sorted(set(merge(ntop.java_rmi_ports, np.java_rmi_ports))))
        mssqlPorts = list(sorted(set(merge(ntop.mssql_ports, np.mssql_ports))))
        mysqlPorts = list(sorted(set(merge(ntop.mysql_ports, np.mysql_ports))))
        cassandraPorts = list(sorted(set(merge(ntop.cassandra_ports, np.cassandra_ports))))
        mongoPorts = list(sorted(set(merge(ntop.mongo_ports, np.mongo_ports))))
        pop3Ports = list(sorted(set(merge(ntop.pop3_ports, np.pop3_ports))))
        kerberosPorts = list(sorted(set(merge(ntop.kerberos_ports, np.kerberos_ports))))
        fingerPorts = list(sorted(set(merge(ntop.finger_ports, np.finger_ports))))
        tcpPorts = list(sorted(set(merge(ntop.tcp_ports, np.tcp_ports))))
        string_tcp_ports = ",".join(map(str, tcpPorts))
        unp = nmapParser.NmapParserFunk(self.target)
        unp.openUdpPorts()
        snmpPorts = unp.snmp_ports
        ikePorts = unp.ike_ports
        c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
        unsorted_commands = []
        unsorted_commands.append(c.getCmd("nmap", "nmapVulners", openTcpPorts=string_tcp_ports))
        if len(snmpPorts) != 0:
            if not os.path.exists(c.getPath("snmp", "snmpDir")):
                os.makedirs(c.getPath("snmp", "snmpDir"))
            unsorted_commands.append(c.getCmd("snmp", "snmpwalk"))
            unsorted_commands.append(c.getCmd("snmp", "snmpCheck"))
            unsorted_commands.append(c.getCmd("snmp", "onesixtyone"))
        if len(ikePorts) != 0:
            unsorted_commands.append(c.getCmd("ike", "ikescan"))
            unsorted_commands.append(c.getCmd("ike", "ikescan4500"))
            unsorted_commands.append(c.getCmd("ike", "nmapIke"))
        if len(ftpPorts) != 0:
            string_ftp_ports = ",".join(map(str, ftpPorts))
            unsorted_commands.append(c.getCmd("ftp", "nmapFtp", ftpPorts=string_ftp_ports))
        if len(fingerPorts) != 0:
            if not os.path.exists(c.getPath("finger", "fingerDir")):
                os.makedirs(c.getPath("finger", "fingerDir"))
            for p in fingerPorts:
                unsorted_commands.append(c.getCmd("finger", "fingerUserEnum", p=p))
        if len(smtpPorts) != 0:
            if not os.path.exists(c.getPath("smtp", "smtpDir")):
                os.makedirs(c.getPath("smtp", "smtpDir"))
            for p in smtpPorts:
                unsorted_commands.append(c.getCmd("smtp", "smtpUserEnum", p=p))
        if len(nfsPorts) != 0:
            if not os.path.exists(c.getPath("nfs", "nfsDir")):
                os.makedirs(c.getPath("nfs", "nfsDir"))
            string_nfs_ports = ",".join(map(str, nfsPorts))
            unsorted_commands.append(c.getCmd("nfs", "nmapNfs", nfsPorts=string_nfs_ports))
            unsorted_commands.append(c.getCmd("nfs", "showmount"))
        if len(rpcPorts) != 0:
            if not os.path.exists(c.getPath("rpc", "rpcDir")):
                os.makedirs(c.getPath("rpc", "rpcDir"))
            if not os.path.exists(c.getPath("smb", "smbScan")):
                unsorted_commands.append(c.getCmd("rpc", "enum4linuxRpc"))
            if which("impacket-rpcdump"):
                unsorted_commands.append(c.getCmd("rpc", "rpcdump"))
        if len(cupsPorts) != 0:
            string_cups_ports = ",".join(map(str, cupsPorts))
            unsorted_commands.append(c.getCmd("cups", "nmapCups", cupsPorts=string_cups_ports))
        if len(javaRmiPorts) != 0:
            string_java_rmi_ports = ",".join(map(str, javaRmiPorts))
            unsorted_commands.append(c.getCmd("java", "javaRmiDump", javarmiPorts=string_java_rmi_ports))
            unsorted_commands.append(c.getCmd("java", "javaRmiVulns", javarmiPorts=string_java_rmi_ports))
        if len(sipPorts) != 0:
            if not os.path.exists(c.getPath("sip", "sipDir")):
                os.makedirs(c.getPath("sip", "sipDir"))
            string_sip_ports = ",".join(map(str, sipPorts))
            unsorted_commands.append(c.getCmd("sip", "nmapSip", sipPorts=string_sip_ports))
            unsorted_commands.append(c.getCmd("sip", "svwar"))
        if len(vncPorts) != 0:
            string_vnc_ports = ",".join(map(str, vncPorts))
            unsorted_commands.append(c.getCmd("vnc", "nmapVnc", vncPorts=string_vnc_ports))
        if len(telnetPorts) != 0:
            string_telnet_ports = ",".join(map(str, telnetPorts))
            unsorted_commands.append(c.getCmd("telnet", "nmapTelnet", telnetPorts=string_telnet_ports))
        if len(cassandraPorts) != 0:
            string_cassandra_ports = ",".join(map(str, cassandraPorts))
            unsorted_commands.append(c.getCmd("cassandra", "nmapCassandra", cassandraPorts=string_cassandra_ports))
        if len(mssqlPorts) != 0:
            string_mssql_ports = ",".join(map(str, mssqlPorts))
            unsorted_commands.append(c.getCmd("mssql", "nmapMssql", mssqlPorts=string_mssql_ports, mssqlPort=mssqlPorts[0]))
        if len(mysqlPorts) != 0:
            string_mysql_ports = ",".join(map(str, mysqlPorts))
            unsorted_commands.append(c.getCmd("mysql", "nmapMysql", mysqlPorts=string_mysql_ports))
        if len(mongoPorts) != 0:
            string_mongo_ports = ",".join(map(str, mongoPorts))
            unsorted_commands.append(c.getCmd("mongodb", "nmapMongo", mongoPorts=string_mongo_ports))
        if len(pop3Ports) != 0:
            string_pop3_ports = ",".join(map(str, pop3Ports))
            unsorted_commands.append(c.getCmd("pop3", "nmapPop3", popPorts=string_pop3_ports))
        if len(kerberosPorts) != 0:
            string_kerberos_ports = ",".join(map(str, kerberosPorts))
            unsorted_commands.append(c.getCmd("kerberos", "nmapKerberos", kerberosPorts=string_kerberos_ports))

        set_sorted_cmds = sorted(set(unsorted_commands))
        cmds_to_run = []
        for i in set_sorted_cmds:
            cmds_to_run.append(i)
        self.processes = tuple(cmds_to_run)
