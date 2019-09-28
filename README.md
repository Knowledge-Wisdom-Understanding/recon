# AUTO-RECON

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/fa8f5aab4e434f848e5b7f27bb9eb816)](https://app.codacy.com/app/Knowledge-Wisdom-Understanding/recon?utm_source=github.com&utm_medium=referral&utm_content=Knowledge-Wisdom-Understanding/recon&utm_campaign=Badge_Grade_Dashboard)
[![HitCount](http://hits.dwyl.io/Knowledge-Wisdom-Understanding/https://githubcom/Knowledge-Wisdom-Understanding/recon.svg)](http://hits.dwyl.io/Knowledge-Wisdom-Understanding/https://githubcom/Knowledge-Wisdom-Understanding/recon)

## Features!

- This tool is intended for CTF's and can be fairly noisy. (Not the most stealth conscious tool...)
- All tools in this project are compliant with the OSCP exam rules.
- If Virtual Host Routing is detected, _Auto-Recon_ will add the host names to your /etc/hosts file and continue to enumerate the newly discovered host names.
- DNS enumeration is nerfed to ignore .com .co .eu .uk domains etc... since this tool was designed for CTF's like for instance, "hack the box". It will try to find most .htb domains.
- This project use's various tools and chains them together as needed to enumerate a target based off nmap results.

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
      /___/___      \        /  / |  /___/__          \                   _____
          /  /   _   \______/__/  |______|__|_____ *   \_________________/__/  |___
       __/__/   /_\   \ |  |  \   __\/  _ \|  |       __/ __ \_/ ___\/  _ \|       |
      |   |     ___    \|  |  /|  | (  |_| )  |    |   \  ___/\  \__(  |_| )   |   |
      |___|____/\__\____|____/_|__|\_\____/|__|____|_  /\___  |\___  \____/|___|  /
      gtihub.com/Knowledge-Wisdom-Understanding  \___\/  \__\/  \__\_/      \___\/


usage: python3 recon.py -t 10.10.10.10

An Information Gathering and Enumeration Framework

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        Single IPv4 Target to Scan
  -v, --version         Show Current Version
  -f FILE, --file FILE  File of IPv4 Targets to Scan
  -w WEB, --web WEB     Get open ports for IPv4 address, then only Enumerate
                        Web & and Dns Services
  -b {ftp,smb,http,ssh}, --brute {ftp,smb,http,ssh}
                        Experimental! - Brute Force ssh,smb,ftp, or http. -t,
                        --target is REQUIRED. Must supply only one protocol at
                        a time. Since there are already many stand-alone
                        bruteforce tools out there, for ssh, first valid users
                        will be enumerated before password brute is initiated,
                        when no user or passwords are supplied as options.
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

```shell
python3 recon.py -w 10.10.10.10
```

To Scan + Enumerate all IPv4 addr's in ips.txt file

```shell
python3 recon.py -f ips.txt
```

Brute force ssh users on default port 22 If unique valid users found, brute force passwords

```shell
python3 recon.py -t 10.10.10.10 -b ssh
```

Same as above but for ssh on port 2222 etc...

```shell
python3 recon.py -t 10.10.10.10 -b ssh -p 2222
```

## Demo

| Recon                                                                                                                              | Brute                                                                                                                                  |
| ---------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| <img align="left" width="575" height="363" src="https://github.com/Knowledge-Wisdom-Understanding/recon/blob/master/img/auto.gif"> | <img align="left" width="575" height="363" src="https://github.com/Knowledge-Wisdom-Understanding/recon/blob/master/img/sshBrute.gif"> |

This program is intended to be used in kali linux.
If you notice a bug or have a feature request. Please create an issue or submit a pull request. Thanks!

## Disclaimer

**Usage of recon.py for testing or exploiting websites without prior mutual consistency can be considered as an illegal activity. This tool is intended for CTF machines only. It is the final user's responsibility to obey all applicable local, state and federal laws. Authors assume no liability and are not responsible for any misuse or damage caused by this program.**
