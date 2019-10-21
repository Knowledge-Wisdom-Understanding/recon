# O.G. AUTO-RECON

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/fa8f5aab4e434f848e5b7f27bb9eb816)](https://app.codacy.com/app/Knowledge-Wisdom-Understanding/recon?utm_source=github.com&utm_medium=referral&utm_content=Knowledge-Wisdom-Understanding/recon&utm_campaign=Badge_Grade_Dashboard)
[![HitCount](http://hits.dwyl.io/Knowledge-Wisdom-Understanding/https://githubcom/Knowledge-Wisdom-Understanding/recon.svg)](http://hits.dwyl.io/Knowledge-Wisdom-Understanding/https://githubcom/Knowledge-Wisdom-Understanding/recon)

## Features

- The purpose of O.G. Auto-Recon is to automate the initial information gathering phase and then enumerate based off those results as much as possible.
- This tool is intended for CTF's and can be fairly noisy. (Not the most stealth conscious tool...)
- All tools in this project are compliant with the OSCP exam rules.
- Command syntax can be easily modified in the [Config](../master/config/config.yaml) settings. \$variable names should remain unchanged.
- If Virtual Host Routing is detected, **O.G. Auto-Recon** will add the host names to your /etc/hosts file and continue to enumerate the newly discovered host names.
- DNS enumeration is nerfed to ignore .com .co .eu .uk domains etc... since this tool was designed for CTF's like for instance, "hack the box". It will try to find most .htb domains if dns server's are detected..
- This project use's various stand-alone & custom tools to enumerate a target based off nmap results.
- All Commands and output are logged to a Report folder using the naming context, "IP-ADDRESS-Report/" which will look something like, 10.10.10.10-Report/ with a directory tree structure similar to this [report tree structure](../master/docs/overview.md)

### INSTALLATION

```bash
cd /opt
git clone https://github.com/Knowledge-Wisdom-Understanding/recon.git
cd recon
chmod +x setup.sh
./setup.sh
python3 -m pip install -r requirements.txt
```

### Usage

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

The remaining services module is also dependent on the topports and or fulltcp module.
Now you can skip doing a fulltcp scan if the target is slow. However, be advised,
The UDP nmap scan is bundled with the fulltcp module currently, so skipping fulltcp module
will result in missing some udp enumeration.

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
All the available modules are as follows:

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

```shell
python3 recon.py -t 10.10.10.10 -s topports remaining
```

```shell
python3 recon.py -t 10.10.10.10 -s http httpcms
python3 recon.py -t 10.10.10.10 --service oracle
```

#### Important

- MAKE SURE TO CHECK OUT THE [Config](../master/config/config.yaml) file for all your customization needs :octocat:
- All required non-default kali linux dependencies are included in setup.sh.

## Demo

| Recon                                                                                                                              | Brute                                                                                                                                  |
| ---------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| <img align="left" width="575" height="363" src="https://github.com/Knowledge-Wisdom-Understanding/recon/blob/master/img/auto.gif"> | <img align="left" width="575" height="363" src="https://github.com/Knowledge-Wisdom-Understanding/recon/blob/master/img/sshBrute.gif"> |

This program is intended to be used in kali linux.
If you notice a bug or have a feature request. Please create an issue or submit a pull request. Thanks!

## Fun-Facts

- I am aware that there is another very similar project with the same name Auto-Recon.
- Originally, this project started out as a bash script [Auto-Recon-Bash-Version](https://github.com/Knowledge-Wisdom-Understanding/Auto-Recon) which quickly got out of hand maintenance wise.
- Don't get it twisted :smiling_imp: The name Auto-Recon wasn't bitten. :green_apple:
- Original first commit to bash version [Auto-Recon Original Commit](https://github.com/Knowledge-Wisdom-Understanding/Auto-Recon/commit/2c03459fa0c9844a66ba58097b326340bb4ef662)
- Tib3rius's first commit to his project [Tib3rius Auto-Recon](https://github.com/Tib3rius/AutoRecon/commit/a08eeed021df9025e15361914c7332ef1f37b04e)
- Coincidentally, both projects were created on March 1st, 2019.
- Don't sweat the bozack. :sunglasses:

## Disclaimer

**Usage of recon.py for testing or exploiting websites without prior mutual consistency can be considered as an illegal activity. This tool is intended for CTF machines only. It is the final user's responsibility to obey all applicable local, state and federal laws. Authors assume no liability and are not responsible for any misuse or damage caused by this program.**
