#!/usr/bin/env python3

import os
from subprocess import call, check_output, STDOUT
from lib import nmapParser
import glob
from utils import config_parser


class DefaultLinuxUsers:
    """List of default Linux users that is utilized by the SSH Brute Force
    Classes. Specifically, This list helps ignore default linux users, since
    most of the time, these aren't users that you want to brute force as they
    usually don't have a login shell etc.. Besides root of course however,
    Many times, the root user won't be permitted to SSH into a box unless
    specifically set by the Server Admin."""

    def __init__(self, target):
        self.target = target
        self.default_linux_users = [
            "root",
            "adm",
            "nobody",
            "mysql",
            "daemon",
            "bin",
            "games",
            "sync",
            "lp",
            "mail",
            "sshd",
            "ftp",
            "man",
            "sys",
            "news",
            "uucp",
            "proxy",
            "list",
            "backup",
            "www-data",
            "irc",
            "gnats",
            "systemd-timesync",
            "systemd",
            "systemd-network",
            "systemd-resolve",
            "systemd-bus-proxy",
            "_apt",
            "apt",
            "messagebus",
            "mysqld",
            "ntp",
            "arpwatch",
            "Debian-exim",
            "uuid",
            "uuidd",
            "dnsmasq",
            "postgres",
            "usbmux",
            "rtkit",
            "stunnel4",
            "Debian-snmp",
            "sslh",
            "pulse",
            "avahi",
            "saned",
            "inetsim",
            "colord",
            "_rpc",
            "statd",
            "shutdown",
            "halt",
            "operator",
            "gopher",
            "rpm",
            "dbus",
            "rpc",
            "postfix",
            "mailman",
            "named",
            "exim",
            "rpcuser",
            "ftpuser",
            "nfsnobody",
            "xfs",
            "gdm",
            "htt",
            "webalizer",
            "mailnull",
            "smmsp",
            "squid",
            "netdump",
            "pcap",
            "radiusd",
            "radvd",
            "quagga",
            "wnn",
            "dovecot",
            "avahi-autoipd",
            "libuid",
            "hplip",
            "statd",
            "bind",
            "haldaemon",
            "vcsa",
            "abrt",
            "saslauth",
            "apache",
            "nginx",
            "tcpdump",
            "memcached",
            "liquidsoap",
            "dhcpd",
            "clamav",
            "lxc-dnsmasq",
            "xrdp",
            "speech-dispatcher",
            "kernoops",
            "whoopsie",
            "lightdm",
            "syslog",
        ]


class Cewl:
    """Generate a custom Cewl Wordlist if there is a valid WebServer port that is open.
    This wordlist will be appended to the seclists probable top 1575.txt password list and
    then fed to the SSH brute forcing Classes in lib/brute.py"""

    def __init__(self, target):
        self.target = target

    def CewlWordlist(self):
        np = nmapParser.NmapParserFunk(self.target)
        np.openPorts()
        http_ports = np.http_ports
        htports = []
        if len(http_ports) == 1:
            htports.append(http_ports[0])
        ssl_ports = np.ssl_ports
        slports = []
        if len(ssl_ports) == 1:
            slports.append(ssl_ports[0])
        c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
        if os.path.exists(c.getPath("web", "aquatoneDirUrls")):
            if not os.path.exists(c.getPath("wordlists", "wordlistsDir")):
                os.makedirs(c.getPath("wordlists", "wordlistsDir"))
            url_list = []
            urls_file = c.getPath("web", "aquatoneDirUrls")
            if os.path.exists(urls_file):
                try:
                    with open(urls_file, "r") as uf:
                        for line in uf:
                            if "index.html" in line:
                                url_list.append(line.rstrip())
                            if "index.php" in line:
                                url_list.append(line.rstrip())
                    if len(htports) == 1:
                        url_list.append(f"http://{self.target}:{htports[0]}/")
                    if len(slports) == 1:
                        url_list.append(f"https://{self.target}:{slports[0]}/")
                    wordlist = sorted(set(url_list))
                except FileNotFoundError as fnf_error:
                    print(fnf_error)
                    exit()
                cewl_cmds = []
                if len(wordlist) != 0:
                    counter = 0
                    for url in wordlist:
                        counter += 1
                        cewl_cmds.append(f"""cewl {url} -m 3 -w {c.getPath("wordlists","CewlCounter", counter=counter)}""")
                if len(cewl_cmds) != 0:
                    try:
                        for cmd in cewl_cmds:
                            call(cmd, shell=True)
                    except ConnectionRefusedError as cre_error:
                        print(cre_error)
                words = []
                try:
                    with open(c.getPath("wordlists", "CustomPass1575"), "r") as prob:
                        for line in prob:
                            words.append(line.rstrip())
                    for wl in os.listdir(c.getPath("wordlists", "wordlistsDir")):
                        wlfile = f"""{c.getPath("wordlists","wordlistsDir")}/{wl}"""
                        with open(wlfile, "r") as wlf:
                            for line in wlf:
                                words.append(line.rstrip())
                    set_unique_words = sorted(set(words))
                    unique_words = list(set_unique_words)
                    with open(c.getPath("wordlists", "CewlPlus"), "a") as allwls:
                        string_words = "\n".join(map(str, unique_words))
                        allwls.write(str(string_words))
                except FileNotFoundError as fnf_error:
                    print(fnf_error)


class Wordpress:
    def __init__(self, target):
        self.target = target
        self.wordpress_dirs = ["wordpress", "WordPress", "wp-content"]


class DirsearchURLS:
    """This Class, DirsearchURLS is reponsible for sorting all the found URL's
    from Dirsearches report output and then it will combined them in to one unique
    list that will be fed to Aquatone to generate a nice HTML report that will
    Be opened up in the firefox web browser."""

    def __init__(self, target):
        self.target = target

    def genDirsearchUrlList(self):
        c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
        awkprint = "{print $3}"
        dirsearch_files = []
        dir_list = [
            d
            for d in glob.iglob(c.getPath("report", "reportGlob"), recursive=True)
            if os.path.isdir(d)
        ]
        for d in dir_list:
            reportFile_list = [
                fname
                for fname in glob.iglob(f"{d}/*", recursive=True)
                if os.path.isfile(fname)
            ]
            for rf in reportFile_list:
                if "nmap" not in rf:
                    if "dirsearch" in rf:
                        if not os.path.exists(c.getPath("web", "aquatoneDir")):
                            os.makedirs(c.getPath("web", "aquatoneDir"))
                        dirsearch_files.append(rf)
                    if "nikto" in rf:
                        check_nikto_lines = f"""wc -l {rf} | cut -d ' ' -f 1"""
                        num_lines_nikto = check_output(check_nikto_lines, stderr=STDOUT, shell=True).rstrip()
                        if int(num_lines_nikto) < 100:
                            call(f"cat {rf}", shell=True)

        if len(dirsearch_files) != 0:
            all_dirsearch_files_on_one_line = " ".join(map(str, dirsearch_files))
            url_list_cmd = f"""cat {all_dirsearch_files_on_one_line} | grep -Ev '400|403' | awk '{awkprint}' | sort -u > {c.getPath("web", "aquatoneDirUrls")}"""
            call(url_list_cmd, shell=True)

    def genProxyDirsearchUrlList(self):
        """This Class, genProxyDirsearchUrlList is reponsible for sorting all the found URL's
        from Dirsearches report output and then it will combined them in to one unique
        list that will be fed to Aquatone to generate a nice HTML report that will
        Be opened up in the firefox web browser."""

        c = config_parser.CommandParser(f"{os.getcwd()}/config/config.yaml", self.target)
        if os.path.exists(c.getPath("proxy", "proxyDir")):
            awkprint = "{print $3}"
            dirsearch_files = []
            dir_list = [
                d
                for d in glob.iglob(c.getPath("proxy", "proxyGlob"), recursive=True)
                if os.path.isdir(d)
            ]
            for d in dir_list:
                reportFile_list = [
                    fname
                    for fname in glob.iglob(f"{d}/*", recursive=True)
                    if os.path.isfile(fname)
                ]
                for rf in reportFile_list:
                    if "nmap" not in rf:
                        if "dirsearch" in rf:
                            if not os.path.exists(c.getPath("web", "aquatoneDir")):
                                os.makedirs(c.getPath("web", "aquatoneDir"))
                            dirsearch_files.append(rf)

            if len(dirsearch_files) != 0:
                all_dirsearch_files_on_one_line = " ".join(map(str, dirsearch_files))
                url_list_cmd = f"""cat {all_dirsearch_files_on_one_line} | grep -Ev '400|403' | awk '{awkprint}' | sort -u > {c.getPath("proxy", "aquatoneDirProxyUrls")}"""
                call(url_list_cmd, shell=True)


class ignoreDomains:
    """ignoreDomains Class is used by lib/domainFinder.py to help ignore invalid domain names
    from nmap's top open ports initial script scan."""

    def __init__(self):
        self.ignored = ["localhost", "localdomain"]
        self.ignore = [
            ".nse",
            ".php",
            ".exe",
            ".php5",
            ".php7",
            ".config",
            ".html",
            ".png",
            ".js",
            ".org",
            ".versio",
            ".com",
            ".gif" "",
            ".asp",
            ".aspx",
            ".jpg",
            ".jpeg",
            ".txt",
            ".bak",
            ".note",
            ".secret",
            ".backup",
            ".cgi",
            ".pl",
            ".git",
            ".co",
            ".eu",
            ".uk",
            ".htm",
            ".localdomain",
            "localhost.localdomain",
            ".localhost",
            ".acme",
            ".css",
            ".sol",
            ".py",
            ".c",
            ".name",
            ".tar",
            ".gz",
            ".bz2",
            ".tar.gz",
            ".zip",
            ".web",
            ".user",
            ".pass",
            ".bashrc",
            ".bash",
            ".script",
            ".doc",
            ".docx",
            ".tex",
            ".wks",
            ".wpd",
            ".pdf",
            ".xml",
            ".xls",
            ".xlsx",
            ".main",
            ".go",
            ".htm",
            ".ppt",
            ".pptx",
            ".ods",
            ".sql",
            ".dba",
            ".conf",
            ".test",
            ".file",
            ".login",
            ".hta",
            ".robots",
            ".portcu",
            "locald",
            "localh",
            "127.0.0.1",
            ".jar",
            "jar"
        ]


class topPortsToScan:
    """As the Class name Suggests, This Class contains a list of the Top 200 nmap common ports,
    Plus 136 custom CTFish ports that I've come accross so far whille scanning CTF machines.
    Also, The top Common UDP ports I hand picked out that I see open most often so as not to make
    this auto recon tool take forever as UDP port scans can be very slow."""

    def __init__(self):
        self.topTCP = [
            1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 25, 26, 30, 32, 33, 37, 42, 43, 49, 53, 67, 68, 69, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111, 113, 119, 123, 125, 135, 137, 139, 143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 333, 340, 366, 389, 406, 407, 416, 417, 420, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512, 513, 514, 515, 520, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 779, 783, 787, 800, 801, 808, 843, 859, 873, 879, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 989, 990, 991, 992, 993, 995, 999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106, 1107, 1108, 1109, 1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122, 1123, 1124, 1126, 1130, 1131, 1132, 1137, 1138, 1141, 1145, 1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175, 1183, 1185, 1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236, 1244, 1247, 1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328, 1334, 1352, 1337, 1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501, 1503, 1521, 1524, 1533, 1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688, 1700, 1717, 1721, 1723, 1748, 1754, 1755, 1761, 1782, 1783, 1801, 1805, 1812, 1839, 1840, 1862, 1864, 1875, 1880, 1900, 1914, 1935, 1947, 1971, 1972, 1974, 1984, 1998, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016, 2017, 2018, 2019, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045, 2046, 2047, 2048, 2049, 2052, 2053, 2065, 2068, 2077, 2078, 2079, 2080, 2082, 2083, 2086, 2087, 2095, 2096, 2099, 2100, 2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135, 2144, 2160, 2161, 2170, 2179, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288, 2301, 2323, 2366, 2381, 2382, 2383, 2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604, 2605, 2607, 2608, 2638, 2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875, 2909, 2910, 2920, 2967, 2968, 2998, 3000, 3001, 3003, 3005, 3007, 3011, 3013, 3017, 3030, 3031, 3052, 3071, 3077, 3128, 3168, 3211, 3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322, 3325, 3333, 3339, 3351, 3367, 3369, 3372, 3389, 3390, 3404, 3476, 3493, 3517, 3527, 3535, 3546, 3551, 3573, 3580, 3632, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3790, 3800, 3801, 3809, 3814, 3826, 3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998, 4000, 4001, 4006, 4045, 4111, 4125, 4126,
            4129, 4190, 4224, 4242, 4279, 4321, 4343, 4443, 4445, 4446, 4449, 4550, 4555, 4559, 4567, 4662, 4848, 4899, 4900, 4998, 5000, 5001, 5003, 5004, 5009, 5030, 5033, 5038, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100, 5101, 5102, 5120, 5190, 5200, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298, 5353, 5355, 5357, 5405, 5414, 5431, 5432, 5440, 5500, 5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678, 5679, 5718, 5722, 5730, 5800, 5802, 5810, 5811, 5815, 5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901, 5904, 5906, 5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959, 5963, 5985, 5987, 5989, 5998, 6000, 6001, 6002, 6004, 6007, 6009, 6022, 6025, 6059, 6100, 6101, 6106, 6112, 6123, 6129, 6156, 6200, 6346, 6389, 6464, 6502, 6510, 6532, 6543, 6547, 6565, 6567, 6580, 6646, 6666, 6669, 6686, 6689, 6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201, 7331, 7402, 7411, 7435, 7443, 7496, 7512, 7625, 7627, 7676, 7680, 7741, 7744, 7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999, 8000, 8001, 8002, 8007, 8008, 8009, 8010, 8011, 8014, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8088, 8090, 8093, 8099, 8100, 8180, 8181, 8192, 8194, 8200, 8222, 8228, 8254, 8290, 8292, 8300, 8333, 8383, 8400, 8402, 8443, 8500, 8600, 8649, 8651, 8652, 8654, 8701, 8800, 8808, 8873, 8880, 8888, 8899, 8994, 9000, 9001, 9003, 9009, 9011, 9040, 9050, 9071, 9080, 9081, 9090, 9091, 9099, 9100, 9102, 9103, 9110, 9111, 9200, 9201, 9207, 9220, 9255, 9290, 9389, 9415, 9418, 9485, 9500, 9502, 9503, 9505, 9535, 9575, 9593, 9595, 9618, 9666, 9810, 9876, 9878, 9898, 9900, 9917, 9929, 9943, 9944, 9968, 9998, 9999, 10000, 10001, 10004, 10009, 10010, 10012, 10024, 10025, 10082, 10180, 10215, 10243, 10443, 10566, 10616, 10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13337, 13456, 13722, 13782, 13783, 14000, 14238, 14441, 14442, 15000, 15002, 15004, 15660, 15742, 16000, 16001, 16012, 16016, 16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101, 19283, 19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20048, 20221, 20222, 20828, 21571, 22000, 22022, 22222, 22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352, 27353, 27355, 27356, 27715, 27900, 28201, 30000, 30080, 30443, 30718, 30951, 31038, 31337, 32768, 32771, 32785, 32812, 33333, 33354, 33899, 34571, 34573, 34994, 35500, 36013, 37298, 38292, 40193, 40911, 41511, 41664, 41817, 42069, 42452, 42510, 43523, 43810, 43899, 44176, 44442, 44443, 44444, 44501, 45100, 47001, 48080, 48215, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49162, 49163, 49164, 49165, 49166, 49167, 49168, 49169, 49171, 49172, 49174, 49175, 49176, 49182, 49185, 49400, 49540, 49664, 49665, 49666, 49667, 49668, 49669, 49670, 49999, 50000, 50003, 50006, 50255, 50300, 50389, 50500, 50636, 50800, 51103, 51493, 52673, 52726, 52822, 52848, 52869, 53260, 53936, 54045, 54328, 54984, 55055, 55056, 55540, 55555, 55600, 56141, 56737, 56738, 57294, 57797, 58080, 60000, 60020, 60443, 61514, 61532, 61900, 62078, 63331, 64623, 64666, 64680, 64831, 64999, 65000, 65129, 65389, 65534, 65535
        ]
        self.topUDP = [
            11,
            53,
            67,
            68,
            69,
            111,
            123,
            135,
            137,
            138,
            139,
            161,
            162,
            407,
            427,
            445,
            500,
            514,
            520,
            623,
            631,
            800,
            998,
            1036,
            1049,
            1419,
            1434,
            1701,
            1885,
            1900,
            2000,
            2148,
            3130,
            4500,
            5060,
            5353,
            9200,
            9876,
        ]


class ignoreURLS:
    def __init__(self):
        self.ignore_urls = [
            ".htaccess.orig.php,"
            ".htaccess_orig.php,"
            ".htaccess~/,"
            ".htaccess_orig/,"
            ".hta/,"
            ".htaccess.bak.php,"
            ".htaccess.orig/,"
            ".htaccess.sample.php,"
            ".htaccess.bak/,"
            ".htaccess.sample/,"
            ".htaccess~.php,"
            ".htaccess.save.php,"
            ".htaccess.save/,"
            ".htaccess.BAK.php,"
            ".htpasswd.bak/,"
            ".htaccess.BAK/,"
            ".htpasswd.php,"
            ".htpasswd-old.php,"
            ".htpasswd_test.php,"
            ".htpasswds.php,"
            ".htaccess.php,"
            ".htpasswrd.php,"
            ".htpasswd.inc/,"
            ".htpasswd-old/,"
            ".htpasswrd/,"
            ".htpasswd_test/,"
            ".htaccess.txt/,"
            ".htpasswd.inc.php,"
            ".htaccess_sc/,"
            ".htusers/,"
            ".ht_wsr.txt.php,"
            ".htpasswd.bak.php,"
            ".hta.php,"
            ".htusers.php,"
            ".htpasswds/,"
            ".ht_wsr.txt/,"
            "icons/,"
            ".htaccess.txt.php,"
            ".htaccess_sc.php,"
            ".htaccessBAK.php,"
            ".htaccessBAK/,"
            ".htaccess-dev/,"
            ".htaccess-dev.php,"
            ".htaccess_extra.php,"
            ".htaccess.bak1.php,"
            ".htaccess.bak1/,"
            ".htaccess-local.php,"
            ".htaccess.old.php,"
            ".htaccess-marco/,"
            ".htaccess_extra/,"
            ".htaccess-local/,"
            ".htaccess.inc/,"
            ".htaccess.old/,"
            ".htaccess-marco.php,"
            ".htaccess.inc.php,"
            ".htaccessOLD.php,"
            ".htaccessOLD2.php,"
            ".htaccessOLD/,"
            ".htaccessOLD2/,"
            ".htgroup.php,"
            ".htgroup/,"
            "server-status/,"
        ]
        self.ignore_precise = [
            "index.php"
        ]


class IgnoreHttpPorts:
    def __init__(self):
        self.ignore_http_ports = [593, 5985, 47001, 49670]
