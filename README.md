# AUTO-RECON

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/fa8f5aab4e434f848e5b7f27bb9eb816)](https://app.codacy.com/app/Knowledge-Wisdom-Understanding/recon?utm_source=github.com&utm_medium=referral&utm_content=Knowledge-Wisdom-Understanding/recon&utm_campaign=Badge_Grade_Dashboard)

## Quickly Enumerate a Target in Kali Linux

![Recon Loco GIF](img/auto.gif)

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

```shell
python3 recon.py -h, --help             show help message and exit
python3 recon.py -t 10.10.10.10        scan target & enumerate based off nmap results
python3 recon.py -w 10.10.10.10         Enumerate Web with larger wordlists
python3 recon.py -f ips.txt            Scan + Enumerate all IPv4 addr's in ips.txt file
python3 recon.py -t 10.10.10.10 -b ssh  Brute force ssh users on default port 22
                                        If unique valid users found, brute force passwords
python3 recon.py -t 10.10.10.10 -b ssh -p 2222 Same as above but for ssh on port 2222 etc...
```

This program is intended to be used in kali linux.
If you notice a bug or have a feature request. Please create an issue or submit a pull request. Thanks!
