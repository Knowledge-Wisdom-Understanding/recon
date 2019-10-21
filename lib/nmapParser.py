#!/usr/bin/env python3

import os
from libnmap.parser import NmapParser
from utils import config_parser
from xml.sax.handler import ContentHandler
from xml.sax import make_parser


class NmapParserFunk:
    """NmapParserFunk will parse all nmap XML reports and return all found TCP and UDP ports as well
    as their service versions, script results, and various other information."""

    def __init__(self, target):
        self.target = target
        ##### SERVICES ###############
        self.services = []
        self.nmap_services = []
        self.udp_nmap_services = []
        self.udp_services = []
        #### Products ################
        self.ssh_product = []
        self.ftp_product = []
        self.smtp_product = []
        self.pop3_product = []
        self.all_products = []
        ##### PORTS ##################
        self.tcp_ports = []
        self.http_ports = []
        self.ssl_ports = []
        self.smb_ports = []
        self.dns_ports = []
        self.proxy_ports = []
        self.ssh_ports = []
        self.oracle_tns_ports = []
        self.ftp_ports = []
        self.smtp_ports = []
        self.ldap_ports = []
        self.java_rmi_ports = []
        self.cups_ports = []
        self.rpc_ports = []
        self.nfs_ports = []
        self.udp_ports = []
        self.sip_ports = []
        self.telnet_ports = []
        self.vnc_ports = []
        self.cassandra_ports = []
        self.mssql_ports = []
        self.mysql_ports = []
        self.mongo_ports = []
        self.pop3_ports = []
        self.kerberos_ports = []
        self.finger_ports = []
        ###### UDP PORTS ############
        self.snmp_ports = []
        self.sip_udp_ports = []
        self.ike_ports = []
        ####### VERSION #############
        self.ssh_version = []
        self.ftp_version = []
        self.smtp_version = []
        ####### BANNER ##############
        self.banners = []
        ####### Extra Info ##########
        self.http_extra = []
        ###### Script Results #######
        self.http_script_results = []
        self.http_script_title = []
        self.ssl_script_results = []
        self.ssh_script_results = []
        #### Proxy Services #########
        self.proxy_nmap_services = []
        self.proxy_services = []
        #### Proxy Ports ############
        self.proxy_tcp_ports = []
        self.proxy_http_ports = []
        self.proxy_ssl_ports = []
        self.proxy_smb_ports = []
        self.proxy_dns_ports = []
        self.proxy_ports2 = []
        self.proxy_ssh_ports = []
        self.proxy_oracle_tns_ports = []
        self.proxy_ftp_ports = []
        self.proxy_smtp_ports = []
        self.proxy_ldap_ports = []
        self.proxy_java_rmi_ports = []
        self.proxy_cups_ports = []
        self.proxy_rpc_ports = []
        self.proxy_nfs_ports = []
        #### Proxy Versions #########
        self.proxy_ssh_version = []

    def openPorts(self):
        """The openPorts function will parse all found ports from the nmap.xml file fed to
        the report variable. All ports will be appended to the lists in __init__ and will
        then be accessible from the NmapParserFunk Class."""
        def parsefile(xmlfile):
            parser = make_parser()
            parser.setContentHandler(ContentHandler())
            parser.parse(xmlfile)

        c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
        if os.path.exists(c.getPath("nmap", "nmap_top_ports_xml")):
            try:
                parsefile(c.getPath("nmap", "nmap_top_ports_xml"))
                report = NmapParser.parse_fromfile(c.getPath("nmap", "nmap_top_ports_xml"))
                self.nmap_services += report.hosts[0].services
                self.nmap_services = sorted(self.nmap_services, key=lambda s: s.port)
                # print(self.nmap_services)
                ignored_windows_http_ports = [5985, 47001]
                for service in self.nmap_services:
                    if "open" not in service.state:
                        continue
                    if "open|filtered" in service.state:
                        continue
                    self.services.append(
                        (
                            service.port,
                            service.service,
                            service.tunnel,
                            service.cpelist,
                            service.banner,
                            service.service_dict.get("product", ""),
                            service.service_dict.get("version", ""),
                            service.service_dict.get("extrainfo", ""),
                            service.scripts_results,
                        )
                    )
                    for service in self.services:
                        if service[0] not in self.tcp_ports:
                            self.tcp_ports.append(service[0])
                        if "ssl" in service[2] or ("ssl" in service[1]):
                            if "imap" not in service[1]:
                                if "pop3" not in service[1]:
                                    if "ldap" not in service[1]:
                                        if service[0] not in self.ssl_ports:
                                            self.ssl_ports.append(service[0])
                                        if service[8] not in self.ssl_script_results:
                                            self.ssl_script_results.append(service[8])
                        if "http" in service[1] and ("ssl/http" not in service[1]) and ("ssl" not in service[2]) and ("ssl" not in service[1]):
                            if "MiniServ" not in service[5]:
                                if "http-proxy" not in service[1]:
                                    if service[0] not in ignored_windows_http_ports:
                                        if service[0] not in self.http_ports:
                                            self.http_ports.append(service[0])
                                        if service[8] not in self.http_script_results:
                                            self.http_script_results.append(service[8])
                        if "netbios-ssn" in service[1]:
                            if service[0] not in self.smb_ports:
                                self.smb_ports.append(service[0])
                        if "microsoft-ds" in service[1]:
                            if service[0] not in self.smb_ports:
                                self.smb_ports.append(service[0])
                        if "domain" in service[1]:
                            if service[0] not in self.dns_ports:
                                self.dns_ports.append(service[0])
                        if "http-proxy" in service[1]:
                            if service[0] not in self.proxy_ports:
                                self.proxy_ports.append(service[0])
                        if "ssh" in service[1]:
                            if service[0] not in self.ssh_ports:
                                self.ssh_ports.append(service[0])
                            if service[5] not in self.ssh_product:
                                self.ssh_product.append(service[5])
                            if service[6] not in self.ssh_version:
                                self.ssh_version.append(service[6])
                            if service[8] not in self.ssh_script_results:
                                self.ssh_script_results.append(service[8])
                        if "oracle-tns" in service[1]:
                            if service[0] != 49160:
                                if service[0] not in self.oracle_tns_ports:
                                    self.oracle_tns_ports.append(service[0])
                        if "ftp" in service[1]:
                            if service[0] not in self.ftp_ports:
                                self.ftp_ports.append(service[0])
                            if service[5] not in self.ftp_product:
                                self.ftp_product.append(service[5])
                            if service[6] not in self.ftp_version:
                                self.ftp_version.append(service[6])
                        if "smtp" in service[1]:
                            if service[0] not in self.smtp_ports:
                                self.smtp_ports.append(service[0])
                            if service[4] not in self.smtp_version:
                                self.smtp_version.append(service[4])
                            if service[5] not in self.smtp_product:
                                self.smtp_product.append(service[5])
                        if "rpcbind" in service[1]:
                            if service[0] not in self.nfs_ports:
                                self.nfs_ports.append(service[0])
                        if "msrpc" in service[1]:
                            if service[0] not in self.rpc_ports:
                                self.rpc_ports.append(service[0])
                        if "ldap" in service[1]:
                            if service[0] not in self.ldap_ports:
                                self.ldap_ports.append(service[0])
                        if "BaseHTTPServer" in service[4]:
                            if service[0] not in self.http_ports:
                                self.http_ports.append(service[0])
                        if "Apache" in service[5] and ("ssl/http" not in service[1]) and ("ssl" not in service[2]) and ("ssl" not in service[1]):
                            if service[0] not in self.http_ports:
                                self.http_ports.append(service[0])
                        if "telnet" in service[1]:
                            if service[0] not in self.telnet_ports:
                                self.telnet_ports.append(service[0])
                        if "asterisk" in service[1]:
                            if service[0] not in self.sip_ports:
                                self.sip_ports.append(service[0])
                        if "vnc" in service[1]:
                            if service[0] not in self.vnc_ports:
                                self.vnc_ports.append(service[0])
                        if "cassandra" in service[1]:
                            if service[0] not in self.cassandra_ports:
                                self.cassandra_ports.append(service[0])
                        if "ms-sql" in service[1]:
                            if service[0] not in self.mssql_ports:
                                self.mssql_ports.append(service[0])
                        if "mysql" in service[1]:
                            if service[0] not in self.mysql_ports:
                                self.mysql_ports.append(service[0])
                        if "finger" in service[1]:
                            if service[0] not in self.finger_ports:
                                self.finger_ports.append(service[0])
                        if "mongod" in service[1]:
                            if service[0] not in self.mongo_ports:
                                self.mongo_ports.append(service[0])
                        if "pop3" in service[1]:
                            if service[0] not in self.pop3_ports:
                                self.pop3_ports.append(service[0])
                        if "kerberos" in service[1]:
                            if service[0] not in self.kerberos_ports:
                                self.kerberos_ports.append(service[0])
                        if "kpasswd" in service[1]:
                            if service[0] not in self.kerberos_ports:
                                self.kerberos_ports.append(service[0])
                        if service[4] not in self.banners:
                            self.banners.append(service[4])
                        if service[5] not in self.all_products:
                            self.all_products.append(service[5])

                if len(self.http_script_results) != 0:
                    for t in self.http_script_results[0]:
                        result = t["id"], t["output"]
                        if "http-title" in result:
                            if result[1] not in self.http_script_title:
                                self.http_script_title.append(result[1])

                # Print Statements for Debugging Purposes..
                # print("HTTP PORTS:", self.http_ports)
                # if len(self.http_script_results) != 0:
                #     print("HTTP-Script-Results:", self.http_script_results[0])
                # print("ORACLE PORTS:", self.oracle_tns_ports)
                # print("OPEN TCP PORTS:", self.tcp_ports)
                # print("SSL:", self.ssl_ports)
                # print("SMB:", self.smb_ports)
                # print("DNS:", self.dns_ports)
                # print("Services:", self.services)
                # print("SSH:", self.ssh_ports)
                # print("SSH VERSION:", self.ssh_version)
                # print("FTP VERSION:", self.ftp_version)
                # print("FTP PRODUCT", self.ftp_product)
                # print("Proxy Ports:", self.proxy_ports)
                # print("SSH-Product", self.ssh_product)
                if len(self.tcp_ports) > 100:
                    print("Server is Configured to Falsely show all ports as open.")
                    print("ToDo: Create Alternative Scanning Technique to bypass PortSpoof.")
                    print("Exiting for now. Continue Your enumeration Manually, Check if http or https are open")
                    print("by manually trying to view these ports in the web browser. etc. etc.")
                    exit()
            except Exception as e:
                print(f"""{c.getPath("nmap", "nmap_full_tcp_xml")} Cannot Parse Full TCP nmap xml file. {e}""")
                return

    def allOpenPorts(self):
        """The openPorts function will parse all found ports from the FullTcpNmap.xml file fed to
        the report variable. All ports will be appended to the lists in __init__ and will
        then be accessible from the NmapParserFunk Class."""
        def parsefile(xmlfile):
            parser = make_parser()
            parser.setContentHandler(ContentHandler())
            parser.parse(xmlfile)

        c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
        if os.path.exists(c.getPath("nmap", "nmap_full_tcp_xml")):
            try:
                parsefile(c.getPath("nmap", "nmap_full_tcp_xml"))
                report = NmapParser.parse_fromfile(c.getPath("nmap", "nmap_full_tcp_xml"))
                self.nmap_services += report.hosts[0].services
                self.nmap_services = sorted(self.nmap_services, key=lambda s: s.port)
                # print(self.nmap_services)
                ignored_windows_http_ports = [5985, 47001]
                for service in self.nmap_services:
                    if "open" not in service.state:
                        continue
                    if "open|filtered" in service.state:
                        continue
                    self.services.append(
                        (
                            service.port,
                            service.service,
                            service.tunnel,
                            service.cpelist,
                            service.banner,
                            service.service_dict.get("product", ""),
                            service.service_dict.get("version", ""),
                            service.service_dict.get("extrainfo", ""),
                            service.scripts_results,
                        )
                    )
                    for service in self.services:
                        if service[0] not in self.tcp_ports:
                            self.tcp_ports.append(service[0])
                        if "ssl" in service[2] or ("ssl" in service[1]):
                            if "imap" not in service[1]:
                                if "pop3" not in service[1]:
                                    if "ldap" not in service[1]:
                                        if service[0] not in self.ssl_ports:
                                            self.ssl_ports.append(service[0])
                                        if service[8] not in self.ssl_script_results:
                                            self.ssl_script_results.append(service[8])
                        if "http" in service[1] and ("ssl/http" not in service[1]) and ("ssl" not in service[2]) and ("ssl" not in service[1]):
                            if "MiniServ" not in service[5]:
                                if "http-proxy" not in service[1]:
                                    if service[0] not in ignored_windows_http_ports:
                                        if service[0] not in self.http_ports:
                                            self.http_ports.append(service[0])
                                        if service[8] not in self.http_script_results:
                                            self.http_script_results.append(service[8])
                        if "netbios-ssn" in service[1]:
                            if service[0] not in self.smb_ports:
                                self.smb_ports.append(service[0])
                        if "microsoft-ds" in service[1]:
                            if service[0] not in self.smb_ports:
                                self.smb_ports.append(service[0])
                        if "domain" in service[1]:
                            if service[0] not in self.dns_ports:
                                self.dns_ports.append(service[0])
                        if "http-proxy" in service[1]:
                            if service[0] not in self.proxy_ports:
                                self.proxy_ports.append(service[0])
                        if "ssh" in service[1]:
                            if service[0] not in self.ssh_ports:
                                self.ssh_ports.append(service[0])
                            if service[5] not in self.ssh_product:
                                self.ssh_product.append(service[5])
                            if service[6] not in self.ssh_version:
                                self.ssh_version.append(service[6])
                            if service[8] not in self.ssh_script_results:
                                self.ssh_script_results.append(service[8])
                        if "oracle-tns" in service[1]:
                            if service[0] != 49160:
                                if service[0] not in self.oracle_tns_ports:
                                    self.oracle_tns_ports.append(service[0])
                        if "ftp" in service[1]:
                            if service[0] not in self.ftp_ports:
                                self.ftp_ports.append(service[0])
                            if service[5] not in self.ftp_product:
                                self.ftp_product.append(service[5])
                            if service[6] not in self.ftp_version:
                                self.ftp_version.append(service[6])
                        if "smtp" in service[1]:
                            if service[0] not in self.smtp_ports:
                                self.smtp_ports.append(service[0])
                            if service[4] not in self.smtp_version:
                                self.smtp_version.append(service[4])
                            if service[5] not in self.smtp_product:
                                self.smtp_product.append(service[5])
                        if "rpcbind" in service[1]:
                            if service[0] not in self.nfs_ports:
                                self.nfs_ports.append(service[0])
                        if "msrpc" in service[1]:
                            if service[0] not in self.rpc_ports:
                                self.rpc_ports.append(service[0])
                        if "ldap" in service[1]:
                            if service[0] not in self.ldap_ports:
                                self.ldap_ports.append(service[0])
                        if "BaseHTTPServer" in service[4]:
                            if service[0] not in self.http_ports:
                                self.http_ports.append(service[0])
                        if "Apache" in service[5] and ("ssl/http" not in service[1]) and ("ssl" not in service[2]) and ("ssl" not in service[1]):
                            if service[0] not in self.http_ports:
                                self.http_ports.append(service[0])
                        if "telnet" in service[1]:
                            if service[0] not in self.telnet_ports:
                                self.telnet_ports.append(service[0])
                        if "asterisk" in service[1]:
                            if service[0] not in self.sip_ports:
                                self.sip_ports.append(service[0])
                        if "vnc" in service[1]:
                            if service[0] not in self.vnc_ports:
                                self.vnc_ports.append(service[0])
                        if "cassandra" in service[1]:
                            if service[0] not in self.cassandra_ports:
                                self.cassandra_ports.append(service[0])
                        if "ms-sql" in service[1]:
                            if service[0] not in self.mssql_ports:
                                self.mssql_ports.append(service[0])
                        if "mysql" in service[1]:
                            if service[0] not in self.mysql_ports:
                                self.mysql_ports.append(service[0])
                        if "finger" in service[1]:
                            if service[0] not in self.finger_ports:
                                self.finger_ports.append(service[0])
                        if "mongod" in service[1]:
                            if service[0] not in self.mongo_ports:
                                self.mongo_ports.append(service[0])
                        if "pop3" in service[1]:
                            if service[0] not in self.pop3_ports:
                                self.pop3_ports.append(service[0])
                        if "kerberos" in service[1]:
                            if service[0] not in self.kerberos_ports:
                                self.kerberos_ports.append(service[0])
                        if "kpasswd" in service[1]:
                            if service[0] not in self.kerberos_ports:
                                self.kerberos_ports.append(service[0])
                        if service[4] not in self.banners:
                            self.banners.append(service[4])
                        if service[5] not in self.all_products:
                            self.all_products.append(service[5])

                if len(self.http_script_results) != 0:
                    for t in self.http_script_results[0]:
                        result = t["id"], t["output"]
                        if "http-title" in result:
                            if result[1] not in self.http_script_title:
                                self.http_script_title.append(result[1])
            except Exception as e:
                print(f"""{c.getPath("nmap", "nmap_full_tcp_xml")} Cannot Parse Full TCP nmap xml file. {e}""")
                return

        # print("Products", self.all_products)

    def openProxyPorts(self):
        """The openProxyPorts function will parse all found ports from the proxychains nmap xml file fed to
        the report variable. All ports will be appended to the lists in __init__ and will
        then be accessible from the NmapParserFunk Class."""

        def parsefile(xmlfile):
            parser = make_parser()
            parser.setContentHandler(ContentHandler())
            parser.parse(xmlfile)

        c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
        if os.path.exists(c.getPath("nmap", "nmap_proxychain_top_ports")):
            try:
                parsefile(c.getPath("nmap", "nmap_proxychain_top_ports"))
                proxy_report = NmapParser.parse_fromfile(c.getPath("nmap", "nmap_proxychain_top_ports"))
                self.proxy_nmap_services += proxy_report.hosts[0].services
                self.proxy_nmap_services = sorted(
                    self.proxy_nmap_services, key=lambda s: s.port
                )
                ignored_windows_http_ports = [5985, 47001]
                for service in self.proxy_nmap_services:
                    if "open" not in service.state:
                        continue
                    self.proxy_services.append(
                        (
                            service.port,
                            service.service,
                            service.tunnel,
                            service.cpelist,
                            service.banner,
                        )
                    )
                    for service in self.proxy_services:
                        if service[0] not in self.proxy_tcp_ports:
                            self.proxy_tcp_ports.append(service[0])
                        if "ssl" in service[2] or ("ssl" in service[1]):
                            if "imap" not in service[1]:
                                if "pop3" not in service[1]:
                                    if "ldap" not in service[1]:
                                        if service[0] not in self.proxy_ssl_ports:
                                            self.proxy_ssl_ports.append(service[0])
                        if "http" in service[1]:
                            if "ssl" not in service[2]:
                                if "ssl" not in service[1]:
                                    if "http-proxy" not in service[1]:
                                        if service[0] not in ignored_windows_http_ports:
                                            if service[0] not in self.proxy_http_ports:
                                                self.proxy_http_ports.append(service[0])
                        if "netbios-ssn" in service[1]:
                            if service[0] not in self.proxy_smb_ports:
                                self.proxy_smb_ports.append(service[0])
                        if "microsoft-ds" in service[1]:
                            if service[0] not in self.proxy_smb_ports:
                                self.proxy_smb_ports.append(service[0])
                        if "domain" in service[1]:
                            if service[0] not in self.proxy_dns_ports:
                                self.proxy_dns_ports.append(service[0])
                        if "http-proxy" in service[1]:
                            if service[0] not in self.proxy_ports2:
                                self.proxy_ports2.append(service[0])
                        if "ssh" in service[1]:
                            if service[0] not in self.proxy_ssh_ports:
                                self.proxy_ssh_ports.append(service[0])
                            if service[4] not in self.proxy_ssh_version:
                                self.proxy_ssh_version.append(service[4])
                        if "oracle-tns" in service[1]:
                            if service[0] != 49160:
                                if service[0] not in self.proxy_oracle_tns_ports:
                                    self.proxy_oracle_tns_ports.append(service[0])
                        if "ftp" in service[1]:
                            if service[0] not in self.proxy_ftp_ports:
                                self.proxy_ftp_ports.append(service[0])
                        if "smtp" in service[1]:
                            if service[0] not in self.proxy_smtp_ports:
                                self.proxy_smtp_ports.append(service[0])
                        if "rpcbind" in service[1]:
                            if service[0] not in self.proxy_nfs_ports:
                                self.proxy_nfs_ports.append(service[0])
                        if "msrpc" in service[1]:
                            if service[0] not in self.proxy_rpc_ports:
                                self.proxy_rpc_ports.append(service[0])
                        if "ldap" in service[1]:
                            if service[0] not in self.proxy_ldap_ports:
                                self.proxy_ldap_ports.append(service[0])
                        if "BaseHTTPServer" in service[4]:
                            if service[0] not in self.proxy_http_ports:
                                self.proxy_http_ports.append(service[0])

                # print("HTTP PORTS:", self.proxy_http_ports)
                # print("ORACLE PORTS:", self.proxy_oracle_tns_ports)
                # print("OPEN TCP PORTS:", self.proxy_tcp_ports)
                # print("SSL:", self.proxy_ssl_ports)
                # print("SMB:", self.proxy_smb_ports)
                # print("DNS:", self.proxy_dns_ports)
                # print("Services:", self.proxy_services)
                # print("SSH:", self.proxy_ssh_ports)
                # print("SSH VERSION:", self.proxy_ssh_version)
                # print("Proxy Ports2:", self.proxy_ports2)
            except Exception as e:
                print(f"""{c.getPath("nmap", "nmap_top_udp_ports_xml")} Cannot Parse UDP nmap xml file. {e}""")
                return

    def openUdpPorts(self):
        """The openUdpPorts function will parse all found ports from the UDP nmap xml file fed to
        the report variable. All ports will be appended to the lists in __init__ and will
        then be accessible from the NmapParserFunk Class."""

        def parsefile(xmlfile):
            parser = make_parser()
            parser.setContentHandler(ContentHandler())
            parser.parse(xmlfile)

        c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
        if os.path.exists(c.getPath("nmap", "nmap_top_udp_ports_xml")):
            try:
                parsefile(c.getPath("nmap", "nmap_top_udp_ports_xml"))
                report = NmapParser.parse_fromfile(c.getPath("nmap", "nmap_top_udp_ports_xml"))
                self.udp_nmap_services += report.hosts[0].services
                self.udp_nmap_services = sorted(self.udp_nmap_services, key=lambda s: s.port)
                for service in self.udp_nmap_services:
                    if "open" not in service.state:
                        continue
                    if "open|filtered" in service.state:
                        continue
                    self.udp_services.append(
                        (
                            service.port,
                            service.service,
                            service.tunnel,
                            service.cpelist,
                            service.banner,
                        )
                    )
                    for service in self.udp_services:
                        if service[0] not in self.udp_ports:
                            self.udp_ports.append(service[0])
                        if "snmp" in service[1]:
                            if service[0] not in self.snmp_ports:
                                self.snmp_ports.append(service[0])
                        if "sip" in service[1]:
                            if service[0] not in self.sip_udp_ports:
                                self.sip_udp_ports.append(service[0])
                        if "isakmp?" in service[1] or ("isakmp" in service[1]):
                            if service[0] not in self.ike_ports:
                                self.ike_ports.append(service[0])

                # print("SNMP PORTS", self.snmp_ports)
                # print("UDP SERVICES", self.udp_services)
                # print("UDP OPEN PORTS", self.udp_ports)
            except Exception as e:
                print(f"""{c.getPath("nmap", "nmap_top_udp_ports_xml")} Cannot Parse UDP nmap xml file. {e}""")
                return
