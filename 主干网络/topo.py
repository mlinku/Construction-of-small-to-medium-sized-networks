#!/usr/bin/python
from time import sleep

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info, error
from mininet.link import TCLink, Intf
from subprocess import call
from mininet.util import quietRun
import re


def checkIntf(intf):
    "Make sure intf exists and is not configured."
    config = quietRun('ifconfig %s 2>/dev/null' % intf, shell=True)
    if not config:
        error('Error:', intf, 'does not exist!\n')
        exit(1)
    ips = re.findall(r'\d+\.\d+\.\d+\.\d+', config)
    if ips:
        error('Error:', intf, 'has an IP address,'
                              'and is probably in use!\n')
        exit(1)


def myNetwork():
    intfName1 = 'ens33'
    intfName2 = 'ens38'

    info('*** Checking', intfName1, '\n')
    info('*** Checking', intfName2, '\n')
    #checkIntf(intfName1)
    #checkIntf(intfName2)

    net = Mininet(topo=None,
                  build=False,
                  ipBase='192.168.0.0/20')

    info('*** Adding controller\n')
    c0 = net.addController(name='c0',
                           controller=RemoteController,
                           ip='127.0.0.1',
                           protocol='tcp',
                           port=6633)

    info('*** Add switches\n')
    s9 = net.addSwitch('s9', cls=OVSKernelSwitch, failMode='standalone')
    s5 = net.addSwitch('s5', cls=OVSKernelSwitch, dpid='0000000000000005')
    s4 = net.addSwitch('s4', cls=OVSKernelSwitch, dpid='0000000000000004')
    s11 = net.addSwitch('s11', cls=OVSKernelSwitch, failMode='standalone')
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch, dpid='0000000000000003')
    s6 = net.addSwitch('s6', cls=OVSKernelSwitch, dpid='0000000000000006')
    s10 = net.addSwitch('s10', cls=OVSKernelSwitch, failMode='standalone')
    s7 = net.addSwitch('s7', cls=OVSKernelSwitch, dpid='0000000000000007')
    s8 = net.addSwitch('s8', cls=OVSKernelSwitch, failMode='standalone')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch, dpid='0000000000000001')
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch, dpid='0000000000000002')
    dhcp = net.addSwitch('dhcp', cls=OVSKernelSwitch, dpid='0000000000000008')

    info('*** Add hosts\n')
    h8 = net.addHost('h8', cls=Host,ip='0.0.0.0')
    h9 = net.addHost('h9', cls=Host,ip='0.0.0.0')
    #h4 = net.addHost('h4', cls=Host, ip='192.168.2.60/24', defaultRoute='via 192.168.2.254')
    h4 = net.addHost('h4', cls=Host,ip='0.0.0.0')
    h7 = net.addHost('h7', cls=Host,ip='0.0.0.0')
    #h1 = net.addHost('h1', cls=Host, ip='192.168.1.60/24', defaultRoute='via 192.168.1.254')
    h1 = net.addHost('h1', cls=Host,ip='0.0.0.0')
    h3 = net.addHost('h3', cls=Host,ip='0.0.0.0')
    h2 = net.addHost('h2', cls=Host,ip='0.0.0.0')
    h5 = net.addHost('h5', cls=Host,ip='0.0.0.0')
    h6 = net.addHost('h6', cls=Host,ip='0.0.0.0')

    info('*** Add NAT\n')
    # nat = net.addNAT('nat', connect=False, ip='192.168.5.1/20', inNamespace = False)
    _intf_1 = Intf(intfName1, node=s7, port=1)
    _intf_2 = Intf(intfName2, node=s11, port=5)

    info('*** Add links\n')
    # net.addLink(nat, s7, 1, 1)
    net.addLink(s10, s3, 1, 1)
    net.addLink(s9, s2, 1, 1)
    net.addLink(s8, s1, 1, 1)
    net.addLink(s11, s6, 1, 1)
    net.addLink(s6, s7, 2, 2)
    net.addLink(s7, s4, 3, 1)
    net.addLink(s7, s5, 4, 1)
    net.addLink(s4, s5, 2, 2)
    net.addLink(s4, s1, 3, 2)
    net.addLink(s4, s2, 4, 2)
    net.addLink(s4, s3, 5, 2)
    net.addLink(s1, s5, 3, 3)
    net.addLink(s5, s2, 4, 3)
    net.addLink(s5, s3, 5, 3)
    net.addLink(h1, s8, 1, 2)
    net.addLink(s8, h2, 3, 1)
    net.addLink(s8, h3, 4, 1)
    net.addLink(s9, h4, 2, 1)
    net.addLink(s9, h5, 3, 1)
    net.addLink(s9, h6, 4, 1)
    net.addLink(s10, h7, 2, 1)
    net.addLink(s10, h8, 3, 1)
    net.addLink(s10, h9, 4, 1)
    net.addLink(dhcp, s4, 1, 6)
    net.addLink(dhcp, s5, 2, 6)

    info('*** Starting network\n')
    net.build()
    net.start()
    info('*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info('*** Starting switches\n')
    net.get('s9').start([])
    net.get('s5').start([c0])
    net.get('s4').start([c0])
    net.get('s11').start([])
    net.get('s3').start([c0])
    net.get('s6').start([c0])
    net.get('s10').start([])
    net.get('s7').start([c0])
    net.get('s8').start([])
    net.get('s1').start([c0])
    net.get('s2').start([c0])
    net.get('dhcp').start([c0])

    h1.cmd("chmod 777 /etc/resolv.conf")
    h1.cmd("echo $'nameserver 8.8.8.8\noptions edns0\nsearch localdomain example.org'  > /etc/resolv.conf")

    net.get('dhcp').cmd('ifconfig dhcp-eth1 192.168.0.1 netmask 255.255.255.0')
    net.get('dhcp').cmd('ifconfig dhcp-eth2 192.168.0.2 netmask 255.255.255.0')
    net.get('dhcp').cmd(" ip route add 192.168.0.0/21 dev dhcp-eth1 via 192.168.0.254")
    dhcp.cmd(" arp -s 192.168.0.254 00:00:00:00:11:00")
    dhcp.cmd("rm -r /var/lib/dhcp/dhclient.leases")
    dhcp.cmd("rm -r /var/lib/dhcp/dhcpd.leases")
    dhcp.cmd("service isc-dhcp-server restart &")
    input("------------Waiting to start controller and enter space to continue------------")
    info('*** Post configure switches and hosts\n')

    for host in net.hosts:
        if host.params['ip'] == '0.0.0.0':
            get_ip(host)
    info('*** Post configure switches and hosts\n')

    CLI(net)
    net.stop()

def get_ip(host):
    info('*** get ip for {}\n'.format(host))
    host.cmd("dhclient {}-eth1".format(host.name))


if __name__ == '__main__':
    setLogLevel('info')
    myNetwork()

