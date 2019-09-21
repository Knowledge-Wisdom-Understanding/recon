#!/usr/bin/env python3

import os
from lib import nmapParser
from shutil import which
from utils import config_paths


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
        c = config_paths.Configurator(self.target)
        c.createConfig()
        c.cmdConfig()
        unsorted_commands = []
        if len(snmpPorts) != 0:
            if not os.path.exists(f"""{c.getPath("snmpDir")}"""):
                os.makedirs(f"""{c.getPath("snmpDir")}""")
            snmp_walk_cmd = f"""snmpwalk -c public -v2c {self.target} | tee {c.getPath("snmpwalk_log")}"""
            snmp_check_cmd = f"""snmp-check -c public -v 1 -d {self.target} | tee {c.getPath("snmpcheck_log")}"""
            onesixty_one_cmd = f"""onesixtyone -c /usr/share/doc/onesixtyone/dict.txt {self.target} | tee {c.getPath("snmp_onesixtyone_log")}"""
            unsorted_commands.append(snmp_check_cmd)
            unsorted_commands.append(snmp_walk_cmd)
            unsorted_commands.append(onesixty_one_cmd)
        if len(ftpPorts) != 0:
            string_ftp_ports = ",".join(map(str, ftpPorts))
            ftp_enum_cmd = f"""nmap -vv -sV -Pn -p {string_ftp_ports} --script={c.getCmd("ftpScripts")} -oA {c.getPath("nmap_ftp")} {self.target}"""
            unsorted_commands.append(ftp_enum_cmd)
        if len(smtpPorts) != 0:
            if not os.path.exists(f"""{c.getPath("smtpDir")}"""):
                os.makedirs(f"""{c.getPath("smtpDir")}""")
            for p in smtpPorts:
                smtp_cmd = f"""smtp-user-enum -M VRFY -U /usr/share/metasploit-framework/data/wordlists/unix_users.txt -t {self.target} -p {p} 2>&1 | tee {c.getPath("smtp_user_enum")}-{p}.log"""
                unsorted_commands.append(smtp_cmd)
        if len(nfsPorts) != 0:
            if not os.path.exists(f"""{c.getPath("nfsDir")}"""):
                os.makedirs(f"""{c.getPath("nfsDir")}""")
            string_nfs_ports = ",".join(map(str, nfsPorts))
            nfs_cmd = f"""nmap -vv -sV -p {string_nfs_ports} --script=nfs-ls.nse,nfs-statfs.nse,nfs-showmount.nse -oA {c.getPath("nmapNfs")} {self.target}"""
            nfs_cmd_2 = f"""showmount -e {self.target} 2>&1 | tee {c.getPath("nfs_showmount")}"""
            unsorted_commands.append(nfs_cmd)
            unsorted_commands.append(nfs_cmd_2)
        if len(rpcPorts) != 0:
            if not os.path.exists(f"""{c.getPath("rpcDir")}"""):
                os.makedirs(f"""{c.getPath("rpcDir")}""")
            rpc_cmds = (
                f"""enum4linux -av {self.target} | tee {c.getPath("rpcEnum4linux")}"""
            )
            unsorted_commands.append(rpc_cmds)
            if which("impacket-rpcdump" ""):
                rpc_cmd_2 = (
                    f"""impacket-rpcdump @{self.target} | tee {c.getPath("impRpc")}"""
                )
                unsorted_commands.append(rpc_cmd_2)
        if len(cupsPorts) != 0:
            string_cups_ports = ",".join(map(str, cupsPorts))
            cups_cmd = f"""nmap -vv -sV -Pn --script=cups-info.nse,cups-queue-info.nse -p {string_cups_ports} -oA {c.getPath("nmapCups")} {self.target}"""
            unsorted_commands.append(cups_cmd)
        if len(javaRmiPorts) != 0:
            string_java_rmi_ports = ",".join(map(str, javaRmiPorts))
            javaRmi_cmd = f"""nmap -vv -sV -Pn --script=rmi-vuln-classloader.nse -p {string_java_rmi_ports} -oA {c.getPath("nmapJavaRmi")} {self.target}"""
            javaRmi_cmd2 = f"""nmap -vv -sV -Pn --script=rmi-dumpregistry.nse -p {string_java_rmi_ports} -oA {c.getPath("nmapJavaRmiDump")} {self.target}"""
            unsorted_commands.append(javaRmi_cmd)
            unsorted_commands.append(javaRmi_cmd2)
        if len(sipPorts) != 0:
            if not os.path.exists(f"""{c.getPath("sipDir")}"""):
                os.makedirs(f"""{c.getPath("sipDir")}""")
            string_sip_ports = ",".join(map(str, sipPorts))
            sip_nmap_cmd = f"""nmap -sV -p {string_sip_ports} --script='banner,sip-enum-users,sip-methods' -oA {c.getPath("nmapSip")} {self.target}"""
            sip_svwar_cmd2 = (
                f"""svwar -D -m INVITE {self.target} 2>&1 | tee {c.getPath("svWar")}"""
            )
            unsorted_commands.append(sip_nmap_cmd)
            unsorted_commands.append(sip_svwar_cmd2)
        if len(vncPorts) != 0:
            string_vnc_ports = ",".join(map(str, vncPorts))
            vnc_nmap_cmd = f"""nmap -Pn -sV -p {string_vnc_ports} --script='banner,(vnc* or realvnc* or ssl*) and not (brute or broadcast or dos or external or fuzzer) --script-args='unsafe=1' -oA {c.getPath("nmapVNC")} {self.target}"""
            unsorted_commands.append(vnc_nmap_cmd)
        if len(telnetPorts) != 0:
            string_telnet_ports = ",".join(map(str, telnetPorts))
            telnet_nmap_cmd = f"""nmap -Pn -sV -p {string_telnet_ports} --script='banner,telnet-encryption,telnet-ntlm-info' -oA {c.getPath("nmapTelnet")} {self.target}"""
            unsorted_commands.append(telnet_nmap_cmd)
        if len(cassandraPorts) != 0:
            string_cassandra_ports = ",".join(map(str, cassandraPorts))
            cassandra_nmap_cmd = f"""nmap -Pn -sV -p {string_cassandra_ports} --script="banner,(cassandra* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oA {c.getPath("nmapCassandra")} {self.target}"""
            unsorted_commands.append(cassandra_nmap_cmd)
        if len(mssqlPorts) != 0:
            string_mssql_ports = ",".join(map(str, mssqlPorts))
            mssql_nmap_cmd = f"""nmap -Pn -sV -p {string_mssql_ports} --script="banner,(ms-sql* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --script-args="mssql.instance-port={mssqlPorts[0]},mssql.username=sa,mssql.password=sa" -oA {c.getPath("nmapMsSQL")} {self.target}"""
            unsorted_commands.append(mssql_nmap_cmd)
        if len(mysqlPorts) != 0:
            string_mysql_ports = ",".join(map(str, mysqlPorts))
            mysql_nmap_cmd = f"""nmap -Pn -sV -p {string_mysql_ports} --script="banner,(mysql* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oA {c.getPath("nmapMySQL")} {self.target}"""
            unsorted_commands.append(mysql_nmap_cmd)
        if len(mongoPorts) != 0:
            string_mongo_ports = ",".join(map(str, mongoPorts))
            mongo_nmap_cmd = f"""nmap -Pn -sV -p {string_mongo_ports} --script="banner,(mongodb* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oA {c.getPath("nmapMongo")} {self.target}"""
            unsorted_commands.append(mongo_nmap_cmd)
        if len(pop3Ports) != 0:
            string_pop3_ports = ",".join(map(str, pop3Ports))
            pop3_nmap_cmd = f"""nmap -Pn -sV -p {string_pop3_ports} --script="banner,(pop3* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oA {c.getPath("nmapPop3")} {self.target}"""
            unsorted_commands.append(pop3_nmap_cmd)
        if len(kerberosPorts) != 0:
            string_kerberos_ports = ",".join(map(str, kerberosPorts))
            kerberos_nmap_cmd = f"""nmap -Pn -sV -p {string_kerberos_ports} --script="banner,krb5-enum-users" -oA {c.getPath("nmapKerberos")} {self.target}"""
            unsorted_commands.append(kerberos_nmap_cmd)

        set_sorted_cmds = sorted(set(unsorted_commands))
        cmds_to_run = []
        for i in set_sorted_cmds:
            cmds_to_run.append(i)
        mpCmds = tuple(cmds_to_run)
        self.processes = mpCmds

