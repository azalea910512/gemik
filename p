#!/bin/bash
# ******************************************
# Program: OrangKuatSabahanTerkini Servis 
# Website: OrangKuatSabahanTerkini.tk
# Developer: OrangKuatSabahanTerkini
# Nickname: OrangKuatSabahanTerkini
# Date: 22-07-2016
# Last Updated: 22-08-2017
# ******************************************
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
echo ipv4 >> /etc/modules
echo ipv6 >> /etc/modules
sysctl -w net.ipv4.ip_forward=1
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
sed -i 's/#net.ipv6.conf.all.forwarding=1/net.ipv6.conf.all.forwarding=1/g' /etc/sysctl.conf
sysctl -p
clear
echo "
MEMBUANG SPAM PACKAGE
"
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove postfix*;
apt-get -y --purge remove bind*;
clear
echo "
"
sh -c 'echo "deb http://download.webmin.com/download/repository sarge contrib" > /etc/apt/sources.list.d/webmin.list'
wget -qO - http://www.webmin.com/jcameron-key.asc | apt-key add -
apt-get update;
apt-get -y autoremove;
apt-get -y install wget curl;
echo "
"
apt update && apt upgrade -y

# script
wget -O /etc/pam.d/common-password "https://raw.githubusercontent.com/macisvpn/premiumnow/master/common-password"
chmod +x /etc/pam.d/common-password
cd

# disable exim
service exim4 stop
sysv-rc-conf exim4 off

# webmin
apt-get -y install webmin
sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf

# setting port ssh
sed -i 's/Port 22/Port 22/g' /etc/ssh/sshd_config

# install dropbear
apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=444/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
/etc/init.d/dropbear restart
cd
# squid3
apt-get -y install squid3
wget -O /etc/squid3/squid.conf "https://raw.githubusercontent.com/insanpendosa/pendosa/main/squid.conf"
wget -O /etc/squid/squid.conf "https://raw.githubusercontent.com/insanpendosa/pendosa/main/squid.conf"
sed -i "s/ipserver/$myip/g" /etc/squid3/squid.conf
sed -i "s/ipserver/$myip/g" /etc/squid/squid.conf
sed -i "s/ipserver/$myip/g" /etc/squid3/squid.conf
# nginx
apt-get -y install nginx
apt-get -y install php7.0-fpm
apt-get -y install php7.0-cli
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/php/7.0/fpm/pool.d/www.conf "https://raw.githubusercontent.com/KeningauVPS/sslmode/master/www.conf"
mkdir -p /home/vps/public_html
echo "<?php phpinfo(); ?>" > /home/vps/public_html/info.php
wget -O /home/vps/public_html/index.html https://raw.githubusercontent.com/padubang/secret/main/index.html
wget -O /etc/nginx/conf.d/vps.conf "https://raw.githubusercontent.com/ara-rangers/vps/master/vps.conf"
sed -i 's/listen = \/var\/run\/php7.0-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php/7.0/fpm/pool.d/www.conf
service php7.0-fpm restart



mkdir -p /etc/iptables
apt-get install -y openvpn easy-rsa iptables openssl ca-certificates gnupg
apt-get install -y net-tools
cp -r /usr/share/easy-rsa /etc/openvpn
cd /etc/openvpn
cd easy-rsa
sed -i 's|export KEY_COUNTRY="US"|export KEY_COUNTRY="ID"|' /etc/openvpn/easy-rsa/vars
sed -i 's|export KEY_PROVINCE="CA"|export KEY_PROVINCE="ID"|' /etc/openvpn/easy-rsa/vars
sed -i 's|export KEY_CITY="SanFrancisco"|export KEY_CITY="ID"|' /etc/openvpn/easy-rsa/vars
sed -i 's|export KEY_ORG="Fort-Funston"|export KEY_ORG="HunterNblz"|' /etc/openvpn/easy-rsa/vars
sed -i 's|export KEY_EMAIL="me@myhost.mydomain"|export KEY_EMAIL="admin@nabil.my.id"|' /etc/openvpn/easy-rsa/vars
sed -i 's|export KEY_OU="MyOrganizationalUnit"|export KEY_OU="HunterNblz"|' /etc/openvpn/easy-rsa/vars
sed -i 's|export KEY_NAME="EasyRSA"|export KEY_NAME="HunterNblz"|' /etc/openvpn/easy-rsa/vars
sed -i 's|export KEY_OU=changeme|export KEY_OU=HunterNblz|' /etc/openvpn/easy-rsa/vars
cp openssl-1.0.0.cnf openssl.cnf
source ./vars
./clean-all
source vars
rm -rf keys
./clean-all
./build-ca
./build-key-server server
./pkitool --initca
./pkitool --server server
./pkitool client
./build-dh
# generate ta.key
openvpn --genkey --secret keys/ta.key
cp keys/ca.crt /etc/openvpn
cp keys/server.crt /etc/openvpn
cp keys/server.key /etc/openvpn
cp keys/dh2048.pem /etc/openvpn
cp keys/client.key /etc/openvpn
cp keys/client.crt /etc/openvpn
cp keys/ta.key /etc/openvpn

echo 'port 443
proto tcp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
persist-key
persist-tun
keepalive 10 120
duplicate-cn
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so login
client-cert-not-required
username-as-common-name
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
comp-lzo
status server-tcp-1194.log
verb 3' >/etc/openvpn/server-tcp-1194.conf

echo 'port 9994
proto tcp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
persist-key
persist-tun
keepalive 10 120
duplicate-cn
server 10.9.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so login
client-cert-not-required
username-as-common-name
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
comp-lzo
status server-tcp-9994.log
verb 3' >/etc/openvpn/server-tcp-9994.conf

echo 'port 25000
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
persist-key
persist-tun
keepalive 10 120
duplicate-cn
server 20.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so login
client-cert-not-required
username-as-common-name
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
comp-lzo
status server-udp-25000.log
verb 3' >/etc/openvpn/server-udp-25000.conf

systemctl enable openvpn
service openvpn restart
cd

echo "client
dev tun
proto tcp
remote $MYIP 443
http-proxy-retry
http-proxy $MYIP 8080
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3

" >/var/www/html/client-tcp-1194.ovpn

echo "client
dev tun
proto tcp
remote $MYIP 9994
http-proxy-retry
http-proxy $MYIP 8080
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3

" >/var/www/html/client-tcp-9994.ovpn

echo "client
dev tun
proto udp
remote $MYIP 25000
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3

" >/var/www/html/client-udp-25000.ovpn

echo "client
dev tun
proto tcp
remote $MYIP 2905
http-proxy-retry
http-proxy $MYIP 8080
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3

" >/var/www/html/client-ssl-2905.ovpn

echo "client
dev tun
proto tcp
remote $MYIP 9443
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3

" >/var/www/html/client-ssl-9443.ovpn

echo "client
dev tun
proto tcp
remote $MYIP 1194
http-proxy $MYIP 8080
http-proxy-option CUSTOM-HEADER CONNECT HTTP/1.1
http-proxy-option CUSTOM-HEADER Host m.instagram.com
http-proxy-option CUSTOM-HEADER X-Online-Host m.instagram.com
http-proxy-option CUSTOM-HEADER X-Forward-Host m.instagram.com
http-proxy-option CUSTOM-HEADER Connection Keep-Alive
resolv-retry infinite
route-method exe
nobind
persist-key
persist-tun
auth-user-pass
comp-lzo
verb 3

" >/var/www/html/instagram.ovpn

cd
apt-get install -y zip
cd /var/www/html

{
echo "<ca>"
cat "/etc/openvpn/ca.crt"
echo "</ca>"
echo "<cert>"
cat "/etc/openvpn/server.crt"
echo "</cert>"
echo "<key>"
cat "/etc/openvpn/server.key"
echo "</key>"
} >>client-tcp-1194.ovpn

{
echo "<ca>"
cat "/etc/openvpn/ca.crt"
echo "</ca>"
echo "<cert>"
cat "/etc/openvpn/server.crt"
echo "</cert>"
echo "<key>"
cat "/etc/openvpn/server.key"
echo "</key>"
} >>client-tcp-9994.ovpn

{
echo "<ca>"
cat "/etc/openvpn/ca.crt"
echo "</ca>"
echo "<cert>"
cat "/etc/openvpn/server.crt"
echo "</cert>"
echo "<key>"
cat "/etc/openvpn/server.key"
echo "</key>"
} >>client-ssl-9443.ovpn

{
echo "<ca>"
cat "/etc/openvpn/ca.crt"
echo "</ca>"
echo "<cert>"
cat "/etc/openvpn/server.crt"
echo "</cert>"
echo "<key>"
cat "/etc/openvpn/server.key"
echo "</key>"
} >>client-ssl-2905.ovpn

{
echo "<ca>"
cat "/etc/openvpn/ca.crt"
echo "</ca>"
echo "<cert>"
cat "/etc/openvpn/server.crt"
echo "</cert>"
echo "<key>"
cat "/etc/openvpn/server.key"
echo "</key>"
} >>client-udp-25000.ovpn

{
echo "<ca>"
cat "/etc/openvpn/ca.crt"
echo "</ca>"
echo "<cert>"
cat "/etc/openvpn/server.crt"
echo "</cert>"
echo "<key>"
cat "/etc/openvpn/server.key"
echo "</key>"
} >>instagram.ovpn

zip client-config.zip client-tcp-1194.ovpn client-tcp-9994.ovpn client-ssl-9443.ovpn client-ssl-2905.ovpn client-udp-25000.ovpn instagram.ovpn
apt-get install -y iptables iptables-persistent netfilter-persistent
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o $NIC -j MASQUERADE
iptables -t nat -A POSTROUTING -s 20.8.0.0/24 -o $NIC -j MASQUERADE
iptables-save > /etc/iptables/rules.v4
service openvpn restart

cp client-tcp-1194.ovpn /home/vps/public_html/
cp client-tcp-1194.ovpn /home/vps/public_html/
cp client-ssl-2905.ovpn /home/vps/public_html/

# install stunnel
apt-get install stunnel4 -y
cat > /etc/stunnel/stunnel.conf <<-END
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
[dropbear]
accept = 442
connect = 127.0.0.1:444

[openvpn]
accept = 587
connect = 127.0.0.1:1194

END

#Setting UFW
ufw allow ssh
ufw allow 443/tcp
sed -i 's|DEFAULT_INPUT_POLICY="DROP"|DEFAULT_INPUT_POLICY="ACCEPT"|' /etc/default/ufw
sed -i 's|DEFAULT_FORWARD_POLICY="DROP"|DEFAULT_FORWARD_POLICY="ACCEPT"|' /etc/default/ufw

# Install BadVPN
wget https://raw.githubusercontent.com/RicKbrL/badvpn/master/easyinstall && bash easyinstall
cd
# menu
wget https://raw.githubusercontent.com/padubang/gans/main/setupmenu && bash setupmenu
clear

cd
# install fail2ban
apt-get -y install fail2ban;service fail2ban restart

# Instal DDOS Flate
if [ -d '/usr/local/ddos' ]; then
	echo; echo; echo "Please un-install the previous version first"
	exit 0
else
	mkdir /usr/local/ddos
fi
clear
echo; echo 'Installing DOS-Deflate 0.6'; echo
echo; echo -n 'Downloading source files...'
wget -q -O /usr/local/ddos/ddos.conf http://www.inetbase.com/scripts/ddos/ddos.conf
echo -n '.'
wget -q -O /usr/local/ddos/LICENSE http://www.inetbase.com/scripts/ddos/LICENSE
echo -n '.'
wget -q -O /usr/local/ddos/ignore.ip.list http://www.inetbase.com/scripts/ddos/ignore.ip.list
echo -n '.'
wget -q -O /usr/local/ddos/ddos.sh http://www.inetbase.com/scripts/ddos/ddos.sh
chmod 0755 /usr/local/ddos/ddos.sh
cp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddos
echo '...done'
echo; echo -n 'Creating cron to run script every minute.....(Default setting)'
/usr/local/ddos/ddos.sh --cron > /dev/null 2>&1
echo '.....done'
echo; echo 'Installation has completed.'
echo 'Config file is at /usr/local/ddos/ddos.conf'
echo 'Please send in your comments and/or suggestions to zaf@vsnl.com'


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
/etc/init.d/squid start
rm -rf ~/.bash_history && history -c
echo "unset HISTFILE" >> /etc/profile

# grep ports 
opensshport="$(netstat -ntlp | grep -i ssh | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
dropbearport="$(netstat -nlpt | grep -i dropbear | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
stunnel4port="$(netstat -nlpt | grep -i stunnel | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
openvpnport="$(netstat -nlpt | grep -i openvpn | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
squidport="$(cat /etc/squid/squid.conf | grep -i http_port | awk '{print $2}')"
nginxport="$(netstat -nlpt | grep -i nginx| grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
# SELASAI SUDAH BOSS! ( AutoscriptByOrangKuatSabahanTerkini )
echo "========================================"  | tee -a log-install.txt
echo "Service Autoscript OrangKuatSabahanTerkini (OrangKuatSabahanTerkini SCRIPT 2017)"  | tee -a log-install.txt
echo "----------------------------------------"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "nginx : http://$myip:80"   | tee -a log-install.txt
echo "Webmin : http://$myip:10000/"  | tee -a log-install.txt
echo "Squid3 : 8080"  | tee -a log-install.txt
echo "OpenSSH : 22"  | tee -a log-install.txt
echo "Dropbear : 443"  | tee -a log-install.txt
echo "OpenVPN  : TCP 1194 (sila dapatkan ovpn dari OrangKuatSabahanTerkini)"  | tee -a log-install.txt
echo "Fail2Ban : [on]"  | tee -a log-install.txt
echo "Timezone : Asia/Kuala_Lumpur"  | tee -a log-install.txt
echo "Menu : type menu to check menu script"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "----------------------------------------"
echo "LOG INSTALL  --> /root/log-install.txt"
echo "----------------------------------------"
echo "========================================"  | tee -a log-install.txt
echo "      PLEASE REBOOT TO TAKE EFFECT !"
echo "========================================"  | tee -a log-install.txt
cat /dev/null > ~/.bash_history && history -c
