# AUTO-RECON

## Quickly Enumerate a Target in Kali Linux

### INSTALLATION

```
cd /opt
git clone https://github.com/Knowledge-Wisdom-Understanding/recon.git
cd recon
chmod +x setup.sh
./setup.sh
python3 -m pip install -r requirements.txt
```

### Usage:

```
python3 recon.py -h, --help             show help message and exit
python3 recon.py -t 10.10.10.155        scan target & enumerate based off nmap results
```

This program is intended to be used in kali linux.
If you notice a bug or have a feature request. Please create an issue or submit a pull request. Thanks!
