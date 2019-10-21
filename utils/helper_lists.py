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
            ".pdf" "",
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
            ".conf" "",
            ".test",
            ".file",
            ".login",
            ".hta",
            ".robots",
            ".portcu",
            "locald",
            "localh"
        ]


class topPortsToScan:
    """As the Class name Suggests, This Class contains a list of the Top 200 nmap common ports,
    Plus 136 custom CTFish ports that I've come accross so far whille scanning CTF machines.
    Also, The top Common UDP ports I hand picked out that I see open most often so as not to make
    this auto recon tool take forever as UDP port scans can be very slow."""

    def __init__(self):
        self.topTCP = [
            1,
            3,
            7,
            9,
            13,
            17,
            19,
            21,
            22,
            23,
            25,
            26,
            37,
            43,
            53,
            67,
            68,
            69,
            79,
            80,
            81,
            82,
            88,
            100,
            106,
            110,
            111,
            113,
            119,
            123,
            135,
            137,
            139,
            143,
            144,
            161,
            179,
            199,
            222,
            254,
            255,
            280,
            311,
            333,
            389,
            420,
            427,
            443,
            444,
            445,
            464,
            465,
            497,
            513,
            514,
            515,
            520,
            543,
            544,
            548,
            554,
            555,
            587,
            593,
            625,
            631,
            636,
            646,
            666,
            777,
            779,
            787,
            808,
            859,
            873,
            879,
            888,
            902,
            911,
            989,
            990,
            991,
            993,
            995,
            999,
            1000,
            1022,
            1024,
            1025,
            1026,
            1027,
            1028,
            1029,
            1030,
            1031,
            1032,
            1033,
            1034,
            1035,
            1036,
            1037,
            1038,
            1039,
            1040,
            1041,
            1044,
            1048,
            1049,
            1050,
            1053,
            1054,
            1056,
            1058,
            1059,
            1064,
            1065,
            1066,
            1069,
            1071,
            1074,
            1080,
            1100,
            1109,
            1110,
            1234,
            1337,
            1433,
            1434,
            1494,
            1515,
            1521,
            1720,
            1723,
            1748,
            1754,
            1755,
            1761,
            1801,
            1808,
            1809,
            1880,
            1900,
            1935,
            1998,
            2000,
            2001,
            2002,
            2003,
            2004,
            2005,
            2006,
            2007,
            2008,
            2009,
            2010,
            2011,
            2012,
            2013,
            2014,
            2015,
            2016,
            2017,
            2018,
            2019,
            2020,
            2030,
            2049,
            2052,
            2053,
            2077,
            2078,
            2079,
            2080,
            2082,
            2083,
            2086,
            2087,
            2095,
            2096,
            2100,
            2103,
            2105,
            2107,
            2121,
            2161,
            2222,
            2301,
            2383,
            2401,
            2601,
            2717,
            2869,
            2967,
            3000,
            3001,
            3128,
            3268,
            3269,
            3306,
            3339,
            3372,
            3389,
            3535,
            3573,
            3632,
            3689,
            3690,
            3703,
            3790,
            3986,
            4000,
            4001,
            4045,
            4190,
            4443,
            4445,
            4555,
            4559,
            4899,
            5000,
            5001,
            5003,
            5009,
            5038,
            5050,
            5051,
            5060,
            5101,
            5120,
            5190,
            5353,
            5355,
            5357,
            5432,
            5555,
            5631,
            5666,
            5722,
            5800,
            5900,
            5901,
            5985,
            6000,
            6001,
            6002,
            6004,
            6022,
            6112,
            6200,
            6464,
            6532,
            6646,
            6666,
            6686,
            7000,
            7070,
            7331,
            7411,
            7680,
            7744,
            7777,
            7778,
            7937,
            7938,
            8000,
            8001,
            8002,
            8008,
            8009,
            8010,
            8014,
            8031,
            8080,
            8081,
            8088,
            8180,
            8228,
            8443,
            8808,
            8880,
            8888,
            9000,
            9001,
            9090,
            9100,
            9102,
            9200,
            9201,
            9255,
            9389,
            9505,
            9810,
            9999,
            10000,
            10001,
            10010,
            10243,
            10443,
            11111,
            13337,
            20048,
            22000,
            22022,
            22222,
            27900,
            30080,
            30443,
            31337,
            32768,
            32771,
            32812,
            33333,
            34994,
            36013,
            37298,
            41664,
            41817,
            42069,
            42452,
            43523,
            43810,
            43899,
            44444,
            47001,
            48215,
            49152,
            49153,
            49154,
            49155,
            49156,
            49157,
            49158,
            49159,
            49160,
            49161,
            49162,
            49164,
            49165,
            49166,
            49168,
            49169,
            49171,
            49172,
            49174,
            49182,
            49185,
            49540,
            49664,
            49665,
            49666,
            49667,
            49668,
            49669,
            49670,
            50000,
            50255,
            52726,
            53260,
            53936,
            54984,
            55540,
            55555,
            56141,
            60000,
            61514,
            64666,
            64831,
            64999,
            65534,
            65535,
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
