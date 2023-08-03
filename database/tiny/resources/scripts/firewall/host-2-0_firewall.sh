sysctl -w net.ipv4.ip_forward=1
iptables -F
iptables -P INPUT DROP
iptables -A INPUT -s 172.16.1.4 -j ACCEPT
iptables -A INPUT -s 34.1.1.0/24 -p icmp -j ACCEPT
iptables -A INPUT -s 34.1.2.0/24 -p icmp -j ACCEPT
iptables -A INPUT -s 34.1.3.0/24 -p icmp -j ACCEPT
iptables -A INPUT -s 34.1.4.0/24 -p icmp -j ACCEPT
iptables -A INPUT -s 34.1.2.2 -p tcp -m tcp --dport 22 -j DROP
iptables -A INPUT -s 34.1.2.0/24 -p tcp -m tcp --sport 22 -j ACCEPT
iptables -A INPUT -s 34.1.4.0/24 -p tcp -m tcp --sport 22 -j ACCEPT
iptables -A INPUT -s 34.1.4.0/24 -p tcp -m tcp --dport 22 -j ACCEPT
iptables-save -c
