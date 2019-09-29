# OverView

- This tool is intended for CTF's and can be fairly noisy. (Not the most stealth conscious tool...)
- All tools in this project are compliant with the OSCP exam rules.
- DNS enumeration is nerfed to ignore .com .co .eu .uk .git etc... since this tool was designed for CTF's. It will find most .htb and .local domains.
- This project use's various tools and chains them together as needed to enumerate a target based off nmap results.
- Using python multiprocessing, services can be scanned very quickly.
- If Virtual Host Routing is detected, _Auto-Recon_ will add them to your /etc/hosts file and continue to enumerate the newly discovered host names.

## Output-Report-Structure

- The directory tree will look something along the lines of this, depending on which services are running.
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
