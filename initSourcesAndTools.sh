#Creating empty config file
echo "{}" >> config.json
#Creating empty programs file
echo "{}" >> programs.json
#Downloading word lists
mkdir -p ./wordlists/subdomains
mkdir -p ./wordlists/directories
wget -O ./wordlists/subdomains/jhaddix_all.txt https://gist.githubusercontent.com/jhaddix/f64c97d0863a78454e44c2f7119c2a6a/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt
wget -O ./wordlists/directories/jhaddix_content_discovery_all.txt https://gist.githubusercontent.com/jhaddix/b80ea67d85c13206125806f0828f4d10/raw/c81a34fe84731430741e0463eb6076129c20c4c0/content_discovery_all.txt 
wget -O ./wordlists/directories/content_discovery_nullenc0de.txt https://gist.githubusercontent.com/nullenc0de/96fb9e934fc16415fbda2f83f08b28e7/raw/146f367110973250785ced348455dc5173842ee4/content_discovery_nullenc0de.txt

#installing pre-reqs
sudo apt-get install python3-venv -y
sudo snap install --classic go
sudo snap install amass
go get github.com/subfinder/subfinder
go get github.com/ffuf/ffuf
sudo apt-get masscan -y
mkdir lib
cd lib
git clone https://github.com/danielmiessler/SecLists.git
git clone https://github.com/sqlmapproject/sqlmap.git
git clone https://github.com/epinna/tplmap
git clone https://github.com/OJ/gobuster.git
git clone https://github.com/maK-/parameth.git
git clone https://github.com/nahamsec/JSParser.git
git clone https://github.com/GerbenJavado/LinkFinder.git
git clone https://github.com/commixproject/commix.git commix
git clone https://github.com/vysecurity/DomLink.git
git clone https://github.com/blechschmidt/massdns.git
cd massdns
make
cd ..
sudo apt-get install git gcc make libpcap-dev -y
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make
cd ..
git clone https://github.com/FortyNorthSecurity/EyeWitness.git
cd ..

sudo chown root:root digAndMasscan.sh
sudo chmod 700 digAndMasscan.sh
sudo chmod +x digAndMasscan.sh
INFILE=$(sudo cat /etc/sudoers | grep "$USER" | grep "digAndMasscan.sh")
[[ ! -z "$INFILE" ]] && echo "$USER already in sudoers" || echo "Add the following to sudoers via visudo: $USER  ALL=(ALL) NOPASSWD: $PWD/digAndMasscan.sh"


# Domained tool install disabled. Buggy 
# sudo apt-get install libldns-dev -y
# git clone https://github.com/TypeError/domained.git
# cd domained
# sudo pip install -r ./ext/requirements.txt
# sudo python domained.py --install