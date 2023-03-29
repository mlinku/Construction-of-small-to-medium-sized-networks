ip tunnel add Tunnel-1 mode gre remote 192.168.168.242 local 192.168.168.133
ip addr add 10.1.2.1/24 dev Tunnel-1
ifconfig Tunnel-1 up
ip route add 192.168.1.0/24 dev Tunnel-1
