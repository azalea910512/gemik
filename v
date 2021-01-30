#!/bin/bash
#
# Original script by fornesia, rzengineer and fawzya
# Mod by admin Hidessh
# ==================================================

# initialisasi var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(wget -qO- ipv4.icanhazip.com);
MYIP2="s/xxxxxxxxx/$MYIP/g";

# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

# update repository
apt update -y

# Install PHP 5.6
apt-get install sudo -y
usermod -aG sudo root

sudo apt -y install ca-certificates apt-transport-https
wget -q https://packages.sury.org/php/apt.gpg -O- | sudo apt-key add -
echo "deb https://packages.sury.org/php/ stretch main" | sudo tee /etc/apt/sources.list.d/php.list

sudo apt update -y
sudo apt install php5.6 -y
sudo apt install php5.6-mcrypt php5.6-mysql php5.6-fpm php5.6-cli php5.6-common php5.6-curl php5.6-mbstring php5.6-mysqlnd php5.6-xml -y

# install webserver
cd
sudo apt-get -y install nginx
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/idtunnel/sshtunnel/master/debian9/nginx-default.conf"
mkdir -p /home/vps/public_html
echo "<?php phpinfo() ?>" > /home/vps/public_html/info.php
wget -O /etc/nginx/conf.d/vps.conf "https://raw.githubusercontent.com/idtunnel/sshtunnel/master/debian9/vhost-nginx.conf"
/etc/init.d/nginx restart

# instal nginx php5.6 
apt-get -y install nginx php5.6-fpm
apt-get -y install nginx php5.6-cli
apt-get -y install nginx php5.6-mysql
apt-get -y install nginx php5.6-mcrypt
sed -i 's/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/g' /etc/php/5.6/cli/php.ini

# cari config php fpm dengan perintah berikut "php --ini |grep Loaded"
sed -i 's/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/g' /etc/php/5.6/cli/php.ini

# Cari config php fpm www.conf dengan perintah berikut "find / \( -iname "php.ini" -o -name "www.conf" \)"
sed -i 's/listen = \/run\/php\/php5.6-fpm.sock/listen = 127.0.0.1:9000/g' /etc/php/5.6/fpm/pool.d/www.conf
cd


# Edit port apache2 ke 8090
wget -O /etc/apache2/ports.conf "https://raw.githubusercontent.com/idtunnel/sshtunnel/master/debian9/apache2.conf"

# Edit port virtualhost apache2 ke 8090
wget -O /etc/apache2/sites-enabled/000-default.conf "https://raw.githubusercontent.com/idtunnel/sshtunnel/master/debian9/virtualhost.conf"

# restart apache2
/etc/init.d/apache2 restart
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
sysctl -p
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
country=ID
state=Indonesia
locality=Cilacap
organization=HunterNblz
organizationalunit=HunterNblz
commonname=HunterNblz
email=admin@nabil.my.id
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
http_port 8888
acl all src 0.0.0.0/0
http_access allow all
access_log /var/log/squid/access.log
visible_hostname TD-LTE/FDD-LTE(nb110.cn)
cache_mgr Welcome_to_use_OpenVPN
#
END
sed -i $MYIP2 /etc/squid/squid.conf;
service squid restart

wget https://raw.githubusercontent.com/padubang/gans/main/setupmenu && bash setupmenu
echo "0 0 * * * root /sbin/reboot" > /etc/cron.d/reboot
chmod +x add-user
clear
echo DONE INSTALL
