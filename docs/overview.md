# OverView

## Configuration

You can change the syntax of enumeration commands in the config/config.yaml file.
Just Make sure not to change the $var variables as doing so will break functionality of
O.G. Auto-Recon.

## Usage

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

To Scan + Enumerate all IPv4 addr's in ips.txt file

```shell
python3 recon.py -f ips.txt
```

To Fuzz all found php urls for parameters, you can use the -F --FUZZ flag with no argument.
The Fuzzer will automatically grab any cookies from the urls and add those cookies to the command
used by parameth.

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
When specifying multiple services to ignore, services MUST be space delimited.
All the available ignore choices are:

```text
http,httpcms,ssl,sslcms,aquatone,smb,dns,ldap,oracle,source,proxy,proxycms,fulltcp,topports,remaining,searchsploit
```

```shell
python3 recon.py -t 10.10.10.10 -i http
python3 recon.py -t 10.10.10.10 -i http ssl
python3 recon.py --target 10.10.10.10 --ignore fulltcp http
```

## Output-Report-Structure

- The directory tree will look something like this, depending on which services are running.

```tree
  .
  ├── aquatone
  │   ├── aquatone
  │   │   ├── aquatone_report.html
  │   │   ├── aquatone_session.json
  │   │   ├── aquatone_urls.txt
  │   │   ├── headers
  │   │   │   └── http**10_10_10_7**80**e0262507914649f3.txt
  │   │   ├── html
  │   │   │   └── http**10_10_10_7**80**e0262507914649f3.html
  │   │   └── screenshots
  │   │   └── http**10_10_10_7**80\_\_e0262507914649f3.png
  │   └── urls.txt
  ├── dns
  ├── nfs
  │   └── nfs-show-mount.txt
  ├── nmap
  │   ├── full-tcp-scan-10.10.10.7.gnmap
  │   ├── full-tcp-scan-10.10.10.7.nmap
  │   ├── full-tcp-scan-10.10.10.7.xml
  │   ├── nfs.gnmap
  │   ├── nfs.nmap
  │   ├── nfs.xml
  │   ├── sip.gnmap
  │   ├── sip.nmap
  │   ├── sip.xml
  │   ├── top-ports-10.10.10.7.gnmap
  │   ├── top-ports-10.10.10.7.nmap
  │   ├── top-ports-10.10.10.7.xml
  │   ├── top-udp-ports.gnmap
  │   ├── top-udp-ports.nmap
  │   ├── top-udp-ports.xml
  │   ├── vulnscan-10.10.10.7.gnmap
  │   ├── vulnscan-10.10.10.7.nmap
  │   └── vulnscan-10.10.10.7.xml
  ├── sip
  │   └── svwar.txt
  ├── smtp
  │   └── smtp-user-enum-port-25.log
  ├── snmp
  ├── ssh
  ├── vulns
  │   ├── all-services.log
  │   ├── smtp.log
  │   └── ssh.log
  ├── web
  │   ├── dirsearch-10000.log
  │   ├── dirsearch-80.log
  │   ├── dirsearch-big-10000.log
  │   ├── dirsearch-big-80.log
  │   ├── eyewitness-10.10.10.7-10000
  │   │   ├── ew.db
  │   │   ├── jquery-1.11.3.min.js
  │   │   ├── open_ports.csv
  │   │   ├── report.html
  │   │   ├── Requests.csv
  │   │   ├── screens
  │   │   │   └── http.10.10.10.7.10000.png
  │   │   ├── source
  │   │   │   └── http.10.10.10.7.10000.txt
  │   │   └── style.css
  │   ├── eyewitness-10.10.10.7-80
  │   │   ├── ew.db
  │   │   ├── jquery-1.11.3.min.js
  │   │   ├── open_ports.csv
  │   │   ├── report.html
  │   │   ├── Requests.csv
  │   │   ├── screens
  │   │   │   └── http.10.10.10.7.png
  │   │   ├── source
  │   │   └── style.css
  │   ├── niktoscan-10000.txt
  │   ├── niktoscan-80.txt
  │   ├── robots-10000.txt
  │   ├── robots-80.txt
  │   ├── wafw00f-10000.txt
  │   ├── wafw00f-80.txt
  │   ├── whatweb-10000.txt
  │   └── whatweb-80.txt
  ├── webSSL
  │   ├── niktoscan-10.10.10.7-443.txt
  │   ├── sslscan-color-10.10.10.7-443.log
  │   ├── wafw00f-10.10.10.7-443.txt
  │   └── whatweb-10.10.10.7-443.txt
  └── wordlists
  ├── all.txt
  └── cewl-1-list.txt
```
