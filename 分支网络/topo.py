#!/usr/bin/python

from mininet.node import Controller, OVSKernelSwitch,  Host,RemoteController
from mininet.log import setLogLevel, info
from mn_wifi.net import Mininet_wifi
from mn_wifi.node import Station, OVSKernelAP
from mn_wifi.cli import CLI
from mn_wifi.link import wmediumd
from mininet.link import TCLink, Intf
from time import sleep

from mn_wifi.wmediumdConnector import interference
from subprocess import call
from mn_wifi.link import wmediumd, _4address



def myNetwork():
    intfName1 = 'ens33'
    intfName2 = 'ens38'
    net = Mininet_wifi(topo=None,
                       build=False,
                       link=wmediumd,
                       wmediumd_mode=interference,
                       ipBase='10.0.0.0/8')

    info( '*** Adding controller\n' )
    c0 = net.addController(name='c0',
                           controller=RemoteController,
                           protocol='tcp',
                           port=6653)

    info( '*** Add switches/APs\n')
    ap2 = net.addAccessPoint('ap2', cls=OVSKernelAP, ssid='ap2-ssid',
                             channel='11', mode='g', position='884.0,624.0,0', range=400,dpid='0000000000000002')
    ap1 = net.addAccessPoint('ap1', cls=OVSKernelAP, ssid='ap1-ssid',
                             channel='1', mode='g', position='458.0,637.0,0', range=400,dpid='0000000000000001')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch,dpid='0000000000000003')

    info( '*** Add hosts/stations\n')
    sta2 = net.addStation('sta2', ip='192.168.6.2/24',
                           position='575.0,714.0,0', range=100 )
    sta3 = net.addStation('sta3', ip='192.168.6.3/24',
                           position='968.0,707.0,0', range=100 )
    sta1 = net.addStation('sta1', ip='192.168.6.6/24',
                           position='348.0,700.0,0', range=100, )

    sta1.cmd("chmod 777 /etc/resolv.conf")
    sta1.cmd("echo $'nameserver 8.8.8.8\noptions edns0\nsearch localdomain example.org'  > /etc/resolv.conf")
    info("*** Configuring Propagation Model\n")
    net.setPropagationModel(model="logDistance", exp=3)

    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()

    info( '*** Add links\n')
    net.addLink(s1,ap1,1,2)
    net.addLink(s1,ap2,2,2)


    _intf_1 = Intf(intfName1, node=s1, port=4)
    _intf_2 = Intf(intfName2, node=s1, port=3)

    net.plotGraph(max_x=1350, max_y=1300)

    info( '*** Starting network\n')
    net.build()



    info( '*** Starting switches/APs\n')
    net.get('ap2').start([c0])
    net.get('ap1').start([c0])
    net.get('s1').start([c0])

    ap1.cmd('')
    sta1.cmd("ip route add default dev sta1-wlan0 via 192.168.6.254")
    sta2.cmd("ip route add default dev sta2-wlan0 via 192.168.6.254")
    sta3.cmd("ip route add default dev sta3-wlan0 via 192.168.6.254")
    

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()

