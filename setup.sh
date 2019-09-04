#!/usr/bin/env bash

# Check if user is root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

DOPE='\e[92m[+]\e[0m'

echo -e "${DOPE} Running: apt-get update -y"
apt-get update -y

echo -e "${DOPE} Downloading dirsearch repository in /opt folder"
cd /opt
git clone https://github.com/maurosoria/dirsearch.git

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

echo -e "${DOPE} Installing Patator"
apt install patator -y
cd /opt
git clone https://github.com/lanjelot/patator.git
cd patator
pip install -r requirements.txt
python setup.py install

echo -e "${DOPE} Installing EyeWitness"
apt install eyewitness -y
cd /opt
git clone https://github.com/FortyNorthSecurity/EyeWitness.git
cd EyeWitness && cd setup
chmod +x setup.sh
./setup.sh

echo -e "${DOPE} Installing ODAT"
apt install odat -y
cd /opt
git clone https://github.com/quentinhardy/odat.git

echo -e "${DOPE} Installing Nmap Vulners & Vulscan scripts"
cd /usr/share/nmap/scripts/
git clone https://github.com/vulnersCom/nmap-vulners.git
git clone https://github.com/scipag/vulscan.git
cd vulscan/utilities/updater
chmod +x updateFiles.sh
./updateFiles.sh

echo -e "${DOPE} Installing Sublist3r"
cd /opt
git clone https://github.com/aboul3la/Sublist3r.git

cd /opt
git clone https://github.com/michenriksen/aquatone.git
cd aquatone
wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
unzip -o aquatone_linux_amd64_1.7.0.zip
apt install chromium -y
ln -s /opt/aquatone/aquatone /usr/local/bin/aquatone

echo "hopefully you have go installed and your go path configured correctly. Other-wise you'll have to install subfinder manually."
echo "trying: go get github.com/subfinder/subfinder"
go get github.com/subfinder/subfinder

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

echo -e "${DOPE} Congratulations, All tools installed successfully!"
