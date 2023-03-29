// 在主干网和分支网虚拟机IP之间搭建GRE隧道并启动
ip tunnel add Tunnel-1 mode gre remote 192.168.106.242 local 192.168.106.171
ifconfig Tunnel-1 up
// 配置隧道的网段
ip addr add 192.168.6.1/24 dev Tunnel-1
// 配置隧道的路由表项
ip route add 192.168.4.0/24 dev Tunnel-1
