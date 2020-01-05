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

echo -e "${DOPE} Downloading dirsearch repository in /opt folder"
cd /opt || exit
git clone https://github.com/maurosoria/dirsearch.git

echo -e "${DOPE} Downloading parameth repository in /opt folder"
cd /opt || exit
git clone https://github.com/maK-/parameth.git
cd parameth || exit
python -m pip install -r requirements.txt

echo -e "${DOPE} Installing magescan and dependencies"
cd /opt || exit
git clone https://github.com/steverobbins/magescan magescan
cd magescan || exit
curl -sS https://getcomposer.org/installer | php
php composer.phar install
apt install php7.3-xml -y
apt install php-guzzlehttp-psr7 -y
php --ini
apt install php7.3-curl -y

echo -e "${DOPE} Installing Evil-Winrm"
cd /opt || exit
git clone https://github.com/Hackplayers/evil-winrm.git
cd evil-winrm || exit
gem install winrm winrm-fs colorize stringio

echo -e "${DOPE} Installing Joomlavs"
cd /opt || exit
git clone https://github.com/rastating/joomlavs.git
cd joomlavs || exit
apt install build-essential patch -y
apt install ruby-dev zlib1g-dev liblzma-dev libcurl4-openssl-dev -y
gem install bundler && bundle install

echo -e "${DOPE} Installing Patator"
apt install patator -y
cd /opt || exit
git clone https://github.com/lanjelot/patator.git
cd patator || exit
python -m pip install -r requirements.txt
python setup.py install

echo -e "${DOPE} Installing EyeWitness"
apt install eyewitness -y
cd /opt || exit
git clone https://github.com/FortyNorthSecurity/EyeWitness.git
cd EyeWitness && cd setup || exit
chmod +x setup.sh
./setup.sh

echo -e "${DOPE} Installing ODAT"
apt install odat -y
cd /opt || exit
git clone https://github.com/quentinhardy/odat.git

echo -e "${DOPE} Cloning Impacket to opt folder"
cd /opt || exit
git clone https://github.com/SecureAuthCorp/impacket.git

echo -e "${DOPE} Cloning PowerShell Mafia's PowerSploit to /opt folder"
cd /opt || exit
git clone https://github.com/PowerShellMafia/PowerSploit.git

echo -e "${DOPE} Installing Seclists"
apt install seclists -y

echo -e "${DOPE} Installing Joomscan"
apt install joomscan -y

echo -e "${DOPE} Installing droopescan"
python -m pip install droopescan

echo -e "${DOPE} Installing Nmap Vulners & Vulscan scripts"
cd /usr/share/nmap/scripts/ || exit
git clone https://github.com/vulnersCom/nmap-vulners.git
git clone https://github.com/scipag/vulscan.git
cd vulscan/utilities/updater || exit
chmod +x updateFiles.sh
./updateFiles.sh

cd /opt || exit
git clone https://github.com/michenriksen/aquatone.git
cd aquatone || exit
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip -o aquatone_linux_amd64_1.7.0.zip
apt install chromium -y
ln -s /opt/aquatone/aquatone /usr/local/bin/aquatone

echo -e "${DOPE} Installing snmp-mibs-downloader. This will beautify snmp-walk output to more human readable format"
apt install snmp-mibs-downloader -y
sed -e '/mibs/ s/^#*/#/' -i /etc/snmp/snmp.conf

echo -e "${DOPE} Installing fierce.py"
cd /opt || exit
git clone https://github.com/mschwager/fierce.git
cd fierce || exit
if type -p pip3; then
    pip3 install -r requirements.txt
else
    python3 -m pip install -r requirements.txt
fi
ln -s /opt/fierce/fierce/fierce.py /usr/local/bin/fierce.py

cd "$cwd" || exit
echo -e "${DOPE} Installing requirements.txt"
python3 -m pip install -r requirements.txt

echo -e "${DOPE} Congratulations, All tools installed successfully!"
