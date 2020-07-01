#Downloading word lists
mkdir -p ./wordlists/subdomains
mkdir -p ./wordlists/directories
wget -O ./wordlists/subdomains/jhaddix_all.txt https://gist.githubusercontent.com/jhaddix/f64c97d0863a78454e44c2f7119c2a6a/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt
wget -O ./wordlists/directories/jhaddix_content_discovery_all.txt https://gist.githubusercontent.com/jhaddix/b80ea67d85c13206125806f0828f4d10/raw/c81a34fe84731430741e0463eb6076129c20c4c0/content_discovery_all.txt 
wget -O ./wordlists/directories/content_discovery_nullenc0de.txt https://gist.githubusercontent.com/nullenc0de/96fb9e934fc16415fbda2f83f08b28e7/raw/146f367110973250785ced348455dc5173842ee4/content_discovery_nullenc0de.txt

cat lib/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt lib/SecLists/Discovery/DNS/deepmagic.com-prefixes-top50000.txt lib/SecLists/Discovery/DNS/subdomains-top1million-110000.txt > wordlists/subdomains/subdomains_merged.txt
uniq -u wordlists/subdomains/subdomains_merged.txt > wordlists/subdomains/subdomains_merged_unique.txt

sudo apt install python-pip -y
sudo apt-get install python3-pip -y
sudo apt-get install python3-venv -y
sudo apt-get install nmap -y
sudo apt-get install git -y
sudo apt-get install masscan -y
sudo snap install --classic go
sudo snap install amass
go get -v github.com/projectdiscovery/subfinder/cmd/subfinder
go get github.com/ffuf/ffuf
go get github.com/tomnomnom/waybackurls
go get github.com/tomnomnom/httprobe
go get -u github.com/tomnomnom/hacks/ettu
go get github.com/haccer/subjack
sudo apt-get masscan -y
pip3 install dnsgen
PATH="$HOME/bin:$HOME/.local/bin:$PATH"
alias pip=pip3

mkdir lib
cd lib
git clone https://github.com/danielmiessler/SecLists.git
git clone https://github.com/OJ/gobuster.git
git clone https://github.com/haccer/subjack.git
git clone https://github.com/blechschmidt/massdns.git
cd massdns
make
cd ..
git clone https://github.com/FortyNorthSecurity/EyeWitness.git
cd EyeWitness
sudo ./Python/setup/setup.sh
cd ..

# sudo chown root:root digAndMasscan.sh
# sudo chmod 700 digAndMasscan.sh
# sudo chmod +x digAndMasscan.sh
# INFILE=$(sudo cat /etc/sudoers | grep "$USER" | grep "digAndMasscan.sh")
# [[ ! -z "$INFILE" ]] && echo "$USER already in sudoers" || echo "Add the following to sudoers via visudo: $USER  ALL=(ALL) NOPASSWD: $PWD/digAndMasscan.sh"

sudo chown root:root masscan.sh
sudo chmod 700 masscan.sh
sudo chmod +x masscan.sh
INFILE=$(sudo cat /etc/sudoers | grep "$USER" | grep "masscan.sh")
[[ ! -z "$INFILE" ]] && echo "$USER already in sudoers" || echo "Add the following to sudoers via visudo: $USER  ALL=(ALL) NOPASSWD: $PWD/masscan.sh"


sudo chown root:root nmapBannerGrab.sh
sudo chmod 700 nmapBannerGrab.sh
sudo chmod +x nmapBannerGrab.sh
INFILE=$(sudo cat /etc/sudoers | grep "$USER" | grep "nmapBannerGrab.sh")
[[ ! -z "$INFILE" ]] && echo "$USER already in sudoers" || echo "Add the following to sudoers via visudo: $USER  ALL=(ALL) NOPASSWD: $PWD/nmapBannerGrab.sh"

pip3 install -r requirements.txt
