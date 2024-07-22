sysctl -w net.ipv4.ip_forward=1
iptables -F
iptables -P INPUT DROP
iptables -A INPUT -s 172.16.1.4 -j ACCEPT
iptables -A INPUT -s 44.1.3.0/24 -p tcp -m tcp --dport 80 -j ACCEPT
iptables -A INPUT -s 44.1.9.0/24 -p tcp -m tcp --dport 21 -j ACCEPT
iptables -A INPUT -s 44.1.9.0/24 -p tcp -m tcp --sport 25 -j ACCEPT
iptables -A INPUT -p tcp --dport 6200 -j ACCEPT
iptables-save > firewall_original
