# Usage

## Examples

```shell
Ex. python3 recon.py -t 10.10.10.10
Ex. python3 recon.py -t 10.10.10.10 -w secret
Ex. python3 recon.py -t 10.10.10.10 -w somedirectory
Ex. python3 recon.py -t 10.10.10.10 -w ' '
Ex. python3 recon.py -f ips.txt
Ex. python3 recon.py -t 10.10.10.10 --FUZZ
Ex. python3 recon.py -t 10.10.10.10 -b ssh
Ex. python3 recon.py -t 10.10.10.10 -b ssh -p 2222
Ex. python3 recon.py -t 10.10.10.10 -b ssh -u bob -P /usr/share/seclists/Passwords/darkc0de.txt
Ex. python3 recon.py -t 10.10.10.10 --ignore http httpcms ssl sslcms aquatone dns
Ex. python3 recon.py -t 10.10.10.10 --ignore ssl sslcms
Ex. python3 recon.py -t 10.10.10.10 --ignore fulltcp topports
Ex. python3 recon.py -t 10.10.10.10 --ignore aquatone
```

```text

       _____________          ____    ________________
      /___/___      \        /  / |  /___/__          \      Mr.P-Millz   _____
      O.G./  /   _   \______/__/  |______|__|_____ *   \_________________/__/  |___
       __/__/   /_\   \ |  |  \   __\/  _ \|  |       __/ __ \_/ ___\/  _ \|       |
      |   |     ___    \|  |  /|  | (  |_| )  |    |   \  ___/\  \__(  |_| )   |   |
      |___|____/\__\____|____/_|__|\_\____/|__|____|_  /\___  |\___  \____/|___|  /
      gtihub.com/Knowledge-Wisdom-Understanding  \___\/  \__\/  \__\_/ v3.6 \___\/


usage: python3 recon.py -t 10.10.10.10

An Information Gathering and Enumeration Framework

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Single IPv4 Target to Scan
  -F, --FUZZ            auto fuzz found urls ending with .php for params
  -v, --version         Show Current Version
  -f FILE, --file FILE  File of IPv4 Targets to Scan
  -w [WEB], --web [WEB]
                        Get open ports for IPv4 address, then only Enumerate
                        Web & and Dns Services. -t,--target must be specified.
                        -w, --web takes a URL as an argument. i.e. python3
                        recon.py -t 10.10.10.10 -w secret
  -i {http,httpcms,ssl,sslcms,aquatone,smb,dns,ldap,removecolor,oracle,source,sort_urls,proxy,proxycms,fulltcp,topports,remaining,searchsploit,peaceout,ftpAnonDL,winrm} [{http,httpcms,ssl,sslcms,aquatone,smb,dns,ldap,removecolor,oracle,source,sort_urls,proxy,proxycms,fulltcp,topports,remaining,searchsploit,peaceout,ftpAnonDL,winrm} ...], --ignore {http,httpcms,ssl,sslcms,aquatone,smb,dns,ldap,removecolor,oracle,source,sort_urls,proxy,proxycms,fulltcp,topports,remaining,searchsploit,peaceout,ftpAnonDL,winrm} [{http,httpcms,ssl,sslcms,aquatone,smb,dns,ldap,removecolor,oracle,source,sort_urls,proxy,proxycms,fulltcp,topports,remaining,searchsploit,peaceout,ftpAnonDL,winrm} ...]
                        Service modules to ignore during scan.
  -s {http,httpcms,ssl,sslcms,aquatone,smb,dns,ldap,removecolor,oracle,source,sort_urls,proxy,proxycms,fulltcp,topports,remaining,searchsploit,peaceout,ftpAnonDL,winrm} [{http,httpcms,ssl,sslcms,aquatone,smb,dns,ldap,removecolor,oracle,source,sort_urls,proxy,proxycms,fulltcp,topports,remaining,searchsploit,peaceout,ftpAnonDL,winrm} ...], --service {http,httpcms,ssl,sslcms,aquatone,smb,dns,ldap,removecolor,oracle,source,sort_urls,proxy,proxycms,fulltcp,topports,remaining,searchsploit,peaceout,ftpAnonDL,winrm} [{http,httpcms,ssl,sslcms,aquatone,smb,dns,ldap,removecolor,oracle,source,sort_urls,proxy,proxycms,fulltcp,topports,remaining,searchsploit,peaceout,ftpAnonDL,winrm} ...]
                        Scan only specified service modules
  -b {ftp,smb,http,ssh}, --brute {ftp,smb,http,ssh}
                        Experimental! - Brute Force ssh,smb,ftp, or http. -t,
                        --target is REQUIRED. Must supply only one protocol at
                        a time. For ssh, first valid users will be enumerated
                        before password brute is initiated, when no user or
                        passwords are supplied as options.
  -p PORT, --port PORT  port for brute forcing argument. If no port specified,
                        default port will be used
  -u USER, --user USER  Single user name for brute forcing, for SSH, if no
                        user specified, will default to
                        wordlists/usernames.txt and bruteforce usernames
  -U USERS, --USERS USERS
                        List of usernames to try for brute forcing. Not yet
                        implimented
  -P PASSWORDS, --PASSWORDS PASSWORDS
                        List of passwords to try. Not required for SSH

```

To scan a single target and enumerate based off of nmap results:

```shell
python3 recon.py -t 10.10.10.10
```

To Enumerate Web with larger wordlists

- If you don't want to specify a directory , you can just enter ' ' as the argument for --web

```shell
python3 recon.py -t 10.10.10.10 -w secret
python3 recon.py -t 10.10.10.10 -w somedirectory
python3 recon.py -t 10.10.10.10 -w ' '
```

Typically, on your first run, you should only specify the -t --target option (python3 recon.py -t 10.10.10.10)
Before you can use the -s --service option to specify specific modules, you must have already ran the topports module.
For instance, if you really wanted to skip all other modules on your first run, and only scan the web after topports,
you could do something like,

```shell
python3 recon.py -t 10.10.10.10 -s topports dns http httpcms ssl sslcms sort_urls aquatone source
```

Or skip web enumeration all together but scan everything else.

```shell
python3 recon.py -t 10.10.10.10 -i dns http httpcms ssl sslcms sort_urls aquatone source
```

The remaining services module is dependent on the fulltcp module.

To Scan + Enumerate all IPv4 addr's in ips.txt file

```shell
python3 recon.py -f ips.txt
```

To Fuzz all found php urls for parameters, you can use the -F --FUZZ flag with no argument.

```shell
python3 recon.py -t 10.10.10.10 --FUZZ
```

Brute force ssh users on default port 22 If unique valid users found, brute force passwords

```shell
python3 recon.py -t 10.10.10.10 -b ssh
```

Same as above but for ssh on port 2222 etc...

```shell
python3 recon.py -t 10.10.10.10 -b ssh -p 2222
python3 recon.py -t 10.10.10.10 -b ssh -p 2222 -u slickrick
```

To ignore certain services from being scanned you can specify the -i , --ignore flag.  
When specifying multiple services to ignore, services MUST be space delimited. Only ignore topports if you have already ran this module
as most other modules are dependent on nmap's initial top ports output.
All the available ignore choices are:

```text
http,httpcms,ssl,sslcms,aquatone,smb,dns,ldap,oracle,source,sort_urls,proxy,proxycms,fulltcp,topports,remaining,searchsploit,peaceout,ftpAnonDL,winrm
```

```shell
python3 recon.py -t 10.10.10.10 -i http
python3 recon.py -t 10.10.10.10 -i http ssl
python3 recon.py --target 10.10.10.10 --ignore fulltcp http
```

You can also specify services that you wish to only scan, similar to the --ignore option, the -s, --service option will only scan the service specified.
Please note that before you can use the -s, --service option, You must have already ran the topports nmap scan as most modules are dependent on nmap's output.
The remaining services module scan is dependent on fulltcp scan module a.k.a. nmap full tcp scan, so if you are only specifying the -s remaining module,
make sure that you have already ran the fulltcp module or you could do

```shell
python3 recon.py -t 10.10.10.10 -s fulltcp remaining
```

```shell
python3 recon.py -t 10.10.10.10 -s http httpcms
python3 recon.py -t 10.10.10.10 --service oracle
```

### Important

- MAKE SURE TO CHECK OUT THE [Config](../master/config/config.yaml) file for all your customization needs :octocat:
- All required non-default kali linux dependencies are included in setup.sh.
