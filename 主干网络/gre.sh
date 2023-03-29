ip tunnel add Tunnel-1 mode gre local 192.168.168.242 remote 192.168.168.133
ip link set Tunnel-1 up
ip addr add 10.1.2.2/24 dev Tunnel-1
ip route add 192.168.6.0/24 dev Tunnel-1

