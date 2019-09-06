# OverView

- This tool is intended for CTF's and can be fairly noisy. (Not the most stealth conscious tool...)
- All tools in this project are compliant with the OSCP exam rules.
- DNS enumeration is nerfed to ignore .com .co .eu .uk .git etc... since this tool was designed for CTF's. It will find most .htb and .local domains.
- This project use's various tools and chains them together as needed to enumerate a target based off nmap results.
- Using python multiprocessing, services can be scanned very quickly.
- If Virtual Host Routing is detected, _Auto-Recon_ will add them to your /etc/hosts file and continue to enumerate the newly discovered host names.
