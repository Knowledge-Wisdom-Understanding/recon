#!/usr/bin/env bash

# Check if user is root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

DOPE='\e[92m[+]\e[0m'
cwd=$(echo "$PWD")

echo -e "${DOPE} Running: apt-get update -y"
apt-get update -y

apt-get install python-pip -y
apt-get install python3-pip -y
apt-get install build-essential python3-dev libldap2-dev libsasl2-dev slapd ldap-utils -y
apt-get install python-dev libssl-dev -y


# Using forked version of dirsearch with a fix that i made. Will change this back once it get's merged into the original dirsearch project.
echo -e "${DOPE} Downloading dirsearch repository in /opt folder"
cd /opt
if [ -d "/opt/dirsearch" ]; then
    :
else
    # git clone https://github.com/maurosoria/dirsearch.git
    git clone --single-branch --branch prevent_added_to_queue_when_non_recursive https://github.com/Knowledge-Wisdom-Understanding/dirsearch.git
fi

echo -e "${DOPE} Cloning enum4linux-ng repository to /opt folder"
cd /opt
git clone https://github.com/cddmp/enum4linux-ng.git



echo -e "${DOPE} Downloading parameth repository in /opt folder"
cd /opt
git clone https://github.com/maK-/parameth.git
cd parameth
python -m pip install -r requirements.txt

export GOPATH="$HOME/go"
export GOROOT="/usr/lib/go"
export GOBIN="$GOPATH/bin"
export PATH="$PATH:$GOPATH/bin"

apt install -y golang

echo -e "${DOPE} Installing kerbrute. Hopefully you have go installed on your system."
go get github.com/ropnop/kerbrute || echo "doesn't look like you have go installed. go get command failed."


echo -e "${DOPE} Installing magescan and dependencies"
cd /opt
git clone https://github.com/steverobbins/magescan magescan
cd magescan
curl -sS https://getcomposer.org/installer | php
php composer.phar install
apt install php7.3-xml -y
apt install php-guzzlehttp-psr7 -y
php --ini
apt install php7.3-curl -y

echo -e "${DOPE} Installing Evil-Winrm"
cd /opt
git clone https://github.com/Hackplayers/evil-winrm.git
cd evil-winrm
gem install winrm winrm-fs colorize stringio
#gem install evil-winrm

echo -e "${DOPE} Installing Joomlavs"
cd /opt
git clone https://github.com/rastating/joomlavs.git
cd joomlavs
apt install build-essential patch -y
apt install ruby-dev zlib1g-dev liblzma-dev libcurl4-openssl-dev -y
gem install bundler && bundle install

echo -e "${DOPE} Installing Patator"
apt install patator -y
cd /opt
git clone https://github.com/lanjelot/patator.git
cd patator
python3 -m pip install -r requirements.txt
python3 setup.py install

echo -e "${DOPE} Installing ODAT"
apt install odat -y
cd /opt
git clone https://github.com/quentinhardy/odat.git

echo -e "${DOPE} Cloning Impacket to opt folder"
cd /opt
git clone https://github.com/SecureAuthCorp/impacket.git
apt install python3-impacket -y
apt install impacket-scripts -y
apt install python-impacket -y

echo -e "${DOPE} Installing enum4linux dependencies"
apt install polenum -y

echo -e "${DOPE} Cloning PowerShell Mafia's PowerSploit to /opt folder"
cd /opt
git clone https://github.com/PowerShellMafia/PowerSploit.git

echo -e "${DOPE} Installing Seclists"
apt install seclists -y

echo -e "${DOPE} Installing Joomscan"
apt install joomscan -y

echo -e "${DOPE} Installing droopescan"
python -m pip install droopescan

echo -e "${DOPE} Installing Nmap Vulners & Vulscan scripts"
cd /usr/share/nmap/scripts/
git clone https://github.com/vulnersCom/nmap-vulners.git
git clone https://github.com/scipag/vulscan.git
cd vulscan/utilities/updater
chmod +x updateFiles.sh
./updateFiles.sh

cd /opt
git clone https://github.com/michenriksen/aquatone.git
cd aquatone
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip -o aquatone_linux_amd64_1.7.0.zip
apt install chromium -y
ln -s /opt/aquatone/aquatone /usr/local/bin/aquatone

echo -e "${DOPE} Installing snmp-mibs-downloader. This will beautify snmp-walk output to more human readable format"
apt install snmp-mibs-downloader -y
sed -e '/mibs/ s/^#*/#/' -i /etc/snmp/snmp.conf

echo -e "${DOPE} Installing fierce.py"
cd /opt
git clone https://github.com/mschwager/fierce.git
cd fierce
if type -p pip3; then
    pip3 install -r requirements.txt
else
    python3 -m pip install -r requirements.txt
fi
ln -s /opt/fierce/fierce/fierce.py /usr/local/bin/fierce.py

apt install python3-ldap -y

cd "$cwd"
echo -e "${DOPE} Installing requirements.txt"
python3 -m pip install -r requirements.txt

echo -e "${DOPE} Symlinking /opt/recon/config/config.yaml to ~/.config/autorecon/config.yaml"
mkdir -p ~/.config/autorecon
cd ~/.config/autorecon
ln -sf /opt/recon/config/config.yaml config.yaml
cd "$cwd"

echo -e "${DOPE} Congratulations, All tools installed successfully!"
