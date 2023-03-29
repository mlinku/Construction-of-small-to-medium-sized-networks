import binascii
from collections import defaultdict
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.topology import event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.topology.api import get_switch, get_all_link, get_link
import copy
import random
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4, ipv6, dhcp, udp, tcp, icmp,ether_types
from ryu.lib import mac

import networkx as nx


class Topo(object):
    def __init__(self, logger):
        self.adjacent = defaultdict(lambda s1s2: None)
        # datapathes
        self.switches = None
        self.host_mac_to = {}
        self.logger = logger
        self.host = None

    def reset(self):
        self.adjacent = defaultdict(lambda s1s2: None)
        self.switches = None
        self.host_mac_to = None

    def get_adjacent(self, s1, s2):
        return self.adjacent.get((s1, s2))

    def set_adjacent(self, s1, s2, port):
        self.adjacent[(s1, s2)] = port

    def findpath(self, src_sw, dst_sw, sign, que, bfspath):
        father = {}
        father[src_sw] = src_sw
        while que != []:
            now = que.pop(0)
            sign[now] = 1
            if now == dst_sw:
                temp = now
                bfspath.append(now)
                while father[temp] != temp:
                    bfspath.append(father[temp])
                    temp = father[temp]
                bfspath = bfspath[::-1]
                return bfspath
            else:
                for u in self.switches:
                    if (self.get_adjacent(now, u) is not None) and (sign[u] != 1):
                        sign[u] = 1
                        que.append(u)
                        father[u] = now
        for u in self.switches:
            print(dst_sw, u, (self.get_adjacent(dst_sw, u) is not None))

    def shortest_path(self, src_sw, dst_sw, first_port, last_port):
        self.logger.info(
            "topo calculate the shortest path from ---{}-{}-------{}-{}".format(first_port, src_sw, dst_sw, last_port))
        self.logger.debug("there is {} swithes".format(len(self.switches)))

        sign = {}
        for s in self.switches:
            sign[s] = 0
        sign[src_sw] = 1

        que = []
        que.append(src_sw)

        bfspath = []
        bfspath = self.findpath(src_sw, dst_sw, sign, que, bfspath)

        print("the shortest path is: ")
        print(bfspath)

        if src_sw == dst_sw:
            path = [src_sw]
        else:
            path = bfspath

        record = []
        inport = first_port

        # s1 s2; s2:s3, sn-1  sn
        for s1, s2 in zip(path[:-1], path[1:]):
            # s1--outport-->s2
            outport = self.get_adjacent(s1, s2)

            record.append((s1, inport, outport))
            inport = self.get_adjacent(s2, s1)

        record.append((dst_sw, inport, last_port))

        # we find a path
        # (s1,inport,outport)->(s2,inport,outport)->...->(dest_switch,inport,outport)
        return record, bfspath


# TODO Port status monitor

class BFSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(BFSController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        # logical switches
        self.datapaths = []
        # ip ->mac
        self.arp_table = {}

        self.topo = Topo(self.logger)
        self.flood_history = {}
        self.buffer = []

        self.arp_history = {}

        # haw_add
        # 记录交换机端口对应IP
        self.switch_adds = {}
        self.edge_switch = []

        # net_information
        self.nat_ip = None
        self.nat_mask = None
        self.net_ip = None
        self.gateway = None
        self.nat_switch_id = None
        self.nat_switch = None
        self.nat_switch_port = None
        self.net_getaway_ip = None

        # icmp nat
        self.icmp_out = {}
        self.icmp_in = {}
        self.icmp_life = {}

        # tcp nat
        self.tcp_out = {}
        self.tcp_in = {}

        # udp nat
        self.udp_out = {}
        self.udp_in = {}

        # DHCP服务器IP及对应交换机的编号
        self.dhcp_ip = None
        self.dhcp_switch = None
        self.dhcp_relay = []
        # VPN网络
        self.vpn_net = []
        self.read_information()



    def read_information(self):
        with open('./information.txt', encoding='utf-8') as file:
            content = file.readlines()

            # 读取NAT信息
            self.nat_ip = content[0].replace('\n', '').replace(' ', '').split('=')[-1].split('/')[0]
            print("-----------------------NAt_ip:  {}---------------------".format(self.nat_ip))

            # 读取NAT mask信息
            self.nat_mask = content[0].replace('\n', '').replace(' ', '').split('=')[-1].split('/')[1]
            print("-----------------------NAt_mask:  {}---------------------".format(self.nat_mask))

            # 读取NAT交换机编号信息
            self.nat_switch_id = int(content[1].replace('\n', '').replace(' ', '').split('=')[-1])
            print("-----------------------NAt_ip:  {}---------------------".format(self.nat_switch_id))

            # 读取NAT交换机端口信息
            self.nat_switch_port = int(content[2].replace('\n', '').replace(' ', '').split('=')[-1])
            print("-----------------------NAt_ip:  {}---------------------".format(self.nat_switch_port))

            # 读取网络网关信息
            self.net_getaway_ip = content[3].replace('\n', '').replace(' ', '').split('=')[-1]
            print("-----------------------NAt_ip:  {}---------------------".format(self.net_getaway_ip))

            # 读取网络信息
            self.net_ip = content[4].replace('\n', '').replace(' ', '').split('=')[-1]
            print("-----------------------Net_ip:  {}---------------------".format(self.net_ip))

            # 读取网关信息
            self.gateway = content[5].replace('\n', '').replace(' ', '').split('=')[-1]
            print("-----------------------gateway:  {}---------------------".format(self.gateway))

            # 读取web 相关信息
            self.serve_host = content[6].replace('\n', '').replace(' ', '').split('=')[-1].split(';')
            for host in self.serve_host:
                self.tcp_out[(host.split(',')[0].split(':')[0], int(host.split(',')[0].split(':')[1]))] = int(host.split(',')[1])
                self.tcp_in[int(host.split(',')[1])] = (host.split(',')[0].split(':')[0], int(host.split(',')[0].split(':')[1]))
            print("-----------------------server_host:  {}---------------------".format(self.serve_host))

            # 读取VPN网络信息
            self.vpn_net = content[7].replace('\n', '').replace(' ', '').split('=')[-1].split(';')
            print("-----------------------vpn_net:  {}---------------------".format(self.vpn_net))

    def _find_dp(self, dpid):
        for dp in self.datapaths:
            if dp.id == dpid:
                return dp
        return None

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def configure_path(self, shortest_path, msg, src_mac, dst_mac):
        # configure shortest path to switches
        datapath = msg.datapath

        ofproto = datapath.ofproto

        parser = datapath.ofproto_parser

        # enumerate the calculated path
        # (s1,inport,outport)->(s2,inport,outport)->...->(dest_switch,inport,outport)
        for switch, inport, outport in shortest_path:
            match = parser.OFPMatch(in_port=inport, eth_src=src_mac, eth_dst=dst_mac,eth_type=ether_types.ETH_TYPE_IP)

            actions = [parser.OFPActionOutput(outport)]

            datapath = self._find_dp(int(switch))
            assert datapath is not None

            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

            mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath,
                match=match,
                idle_timeout=0,
                hard_timeout=0,
                priority=1,
                instructions=inst
            )
            datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, event):

        # msg is an object which desicribes the corresponding OpenFlow message
        msg = event.msg

        datapath = msg.datapath

        # object for the negotiated Openflow version
        ofproto = datapath.ofproto

        parser = datapath.ofproto_parser

        # through which port the packet comes in
        in_port = msg.match['in_port']

        # self.logger.info("From datapath {} port {} come in a packet".format(datapath.id,in_port))

        # get src_mac and dest mac
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dpid = datapath.id

        # drop lldp
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # self.logger.info("LLDP")
            return

        # get source and destination mac address
        dst_mac = eth.dst

        src_mac = eth.src

        # check if this is an arp packet
        arp_pkt = pkt.get_protocol(arp.arp)

        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][src_mac] = in_port

        self.TTLdes()

        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)

        if pkt_ipv4:
            src_ip = pkt_ipv4.src
            dst_ip = pkt_ipv4.dst

        if pkt.get_protocol(ipv6.ipv6):
            match = parser.OFPMatch(eth_type=eth.ethertype)
            actions = []
            self.add_flow(datapath, 1, match, actions)
            return None

        self.logger.info(
            "----------------Received a packet in switch:{}  port:{}   -----------------------------".format(dpid,
                                                                                                             in_port))

        pkt_dhcp = pkt.get_protocol(dhcp.dhcp)
        # 判断是否为dhcp报文

        if pkt_dhcp:
            relay = False
            # 判断是否为开启dhcp中继服务的交换机收到的dhcp报文
            for s, p, g in self.dhcp_relay:
                if dpid == s:
                    self.dhcp_relay_handler(msg, s, p, g)
                    relay = True
                    break
            if not relay:
                self.dhcp_handler(msg)
            return
        # 判断是否为arp报文
        if arp_pkt:
            # 记录ip mac 设备号 端口号
            if arp_pkt.src_ip not in self.arp_table or self.arp_table[arp_pkt.src_ip] != (src_mac, dpid, in_port) and src_mac!=self.switch_adds[(self.nat_switch_id, self.nat_switch_port)]:
                self.arp_table[arp_pkt.src_ip] = (src_mac, dpid, in_port)
                # 查询发送
                self.find_send()
            self.arp_handler(msg)
            return

        else:
            # if pkt_ipv4.src not in self.arp_table
            # 发送到外网：目的为外网，且源不是
            if not (self.ipInSubnet(dst_ip, self.net_ip)) and self.ipInSubnet(src_ip, self.net_ip):
                self.logger.info(
                    "----------------Send a packet to internet, dst_ip: {}   -----------------------------".format(
                        dst_ip))
                self.NAT_out(msg)
                return
            # 外网发送到内网：目的为外网，且源也是外网
            if not (self.ipInSubnet(src_ip, self.net_ip)) and not (self.ipInSubnet(dst_ip, self.net_ip)):
                # self.logger.info(
                #     "----------------Received a packet from internet, src_ip: {}   -----------------------------".format(
                #         src_ip))
                # 进入nat入函数
                self.NAT_in(msg)
                return

            # 查询到目的IP在ARP表中
            if self.find(dst_ip):
                # self.handler()
                self.default_handler(dpid, in_port, src_ip, dst_ip, msg)
            # 未查询到结果
            else:
                self.stor(msg)

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, event):
        self.logger.info("A switch entered.Topology rediscovery...")
        self.switch_status_handler(event)
        # 多调用几次，防止ryu未检测出全部link
        self.logger.info('Topology rediscovery done')

    @set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self, event):
        self.logger.info("A switch leaved.Topology rediscovery...")
        self.switch_status_handler(event)
        self.logger.info('Topology rediscovery done')

    def switch_status_handler(self, event):
        all_switches = copy.copy(get_switch(self, None))
        # 获取交换机的端口地址
        for s in all_switches:
            for port in s.ports:
                self.switch_adds[(s.dp.id, port.port_no)] = port.hw_addr
        self.nat_switch = copy.copy(get_switch(self, self.nat_switch_id))[0]
        self.logger.info('-----------------------------nat switch is: {}'.format(self.nat_switch.dp.id))
        # get all datapathid
        # 获取交换机的ID值
        self.topo.switches = [s.dp.id for s in all_switches]

        self.logger.info("switches {}".format(self.topo.switches))

        self.datapaths = [s.dp for s in all_switches]

        # get link and get port
        all_links = copy.copy(get_link(self, None))

        all_link_stats = [(l.src.dpid, l.dst.dpid, l.src.port_no, l.dst.port_no) for l in all_links]
        self.logger.info("Number of links {}".format(len(all_link_stats)))

        all_link_repr = ''

        for s1, s2, p1, p2 in all_link_stats:
            # weight = random.randint(1, 10)

            self.topo.set_adjacent(s1, s2, p1)
            self.topo.set_adjacent(s2, s1, p2)

            all_link_repr += 's{}p{}--s{}p{}\n'.format(s1, p1, s2, p2)
        self.logger.info("All links:\n" + all_link_repr)

        # 获取边界交换机
        self.edge_switch = []
        intra_port = []
        for l in all_link_stats:
            intra_port.append((l[0], l[2]))
            intra_port.append((l[1], l[3]))
        for s in all_switches:
            for port in s.ports:
                self.logger.info("switch:{}   port:{}".format(s.dp.id, port.port_no))
                if (s.dp.id, port.port_no) not in intra_port:
                    self.edge_switch.append((s, port.port_no))
                    self.logger.info("edge_switch:{}   port:{}".format(s.dp.id, port.port_no))

    def dhcp_relay_handler(self, msg, src_switch, link_port, gateway):
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        pkt_dhcp = pkt.get_protocol(dhcp.dhcp)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_udp = pkt.get_protocol(udp.udp)
        for i in range(len(pkt_dhcp.options.option_list) - 1, -1, -1):
            if pkt_dhcp.options.option_list[i].tag == dhcp.DHCP_MESSAGE_TYPE_OPT:
                dhcp_type = int(str(binascii.hexlify(pkt_dhcp.options.option_list[i].value), encoding="utf-8"))
                break
            # elif pkt_dhcp.options.option_list[i].tag == dhcp.DHCP_REQUESTED_IP_ADDR_OPT:
            #     pkt_dhcp.options.option_list.pop(i)
            #     flag = True

        self.logger.info(
            "----------------Received a DHCP packet in dhcp-relay switch:{}  port:{}  type:{}  "
            "-----------------------------".format(
                src_switch, in_port, dhcp_type))

        if (dhcp_type == dhcp.DHCP_DISCOVER or dhcp.DHCP_REQUEST) and in_port == link_port:
            eth.dst = self.switch_adds[self.dhcp_switch]
            if pkt_ipv4.src == "0.0.0.0" and pkt_ipv4.dst == "255.255.255.255":
                pkt_dhcp.hops += 1
                pkt_dhcp.giaddr = gateway
                pkt_ipv4.src = gateway
                pkt_ipv4.dst = self.dhcp_ip
            pkt_udp.csum = 0
            pkt.serialize()
            msg.data = pkt.data + self.addPadding(len(msg.data) - len(pkt.data))

            if pkt_dhcp.hops <= 16:
                self.send_packet(src_switch, in_port, gateway, self.dhcp_ip, msg, self.switch_adds[self.dhcp_switch],
                                 self.dhcp_switch[0],
                                 self.dhcp_switch[1],
                                 eth.src)
            # 差点逻辑 后面补
        elif (dhcp_type == dhcp.DHCP_OFFER or dhcp.DHCP_ACK) and in_port != link_port:
            # 非广播报文
            if pkt_dhcp.flags == 0:
                eth.dst = pkt_dhcp.chaddr
            else:
                eth.dst = "ff:ff:ff:ff:ff:ff"
            if pkt_dhcp.yiaddr != pkt_ipv4.dst:
                pkt_ipv4.src = gateway
                pkt_ipv4.dst = pkt_dhcp.yiaddr
            pkt_udp.dst_port = 68
            pkt_udp.csum = 0
            pkt.serialize()
            msg.data = pkt.data + self.addPadding(len(msg.data) - len(pkt.data))
            self.send_packet(src_switch, in_port, gateway, pkt_dhcp.yiaddr, msg, eth.dst, src_switch, link_port,
                             eth.src)

    def dhcp_handler(self, msg):
        in_port = msg.match['in_port']
        datapath = msg.datapath
        dpid = datapath.id
        pkt = packet.Packet(msg.data)
        pkt_dhcp = pkt.get_protocol(dhcp.dhcp)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        # pkt_udp = pkt.get_protocol(udp.udp)
        for s, p, g in self.dhcp_relay:
            if g == pkt_dhcp.giaddr:
                self.send_packet(dpid, in_port, pkt_ipv4.src, pkt_ipv4.dst, msg, self.switch_adds[(s, p)], s, p,
                                 eth.src)

    def arp_handler(self, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)

        if eth:
            eth_dst = eth.dst
            eth_src = eth.src

        if eth_dst == mac.BROADCAST_STR and arp_pkt:
            # target ip
            arp_dst_ip = arp_pkt.dst_ip

        if arp_pkt:

            # specify the operation that the sender is performing:1 for request,2 for reply
            opcode = arp_pkt.opcode

            # src ip
            arp_src_ip = arp_pkt.src_ip
            # dst ip
            arp_dst_ip = arp_pkt.dst_ip

            # arp请求
            if opcode == arp.ARP_REQUEST:
                if arp_dst_ip == self.nat_ip or self.ipINvpn(arp_dst_ip):
                    # send arp reply from in port
                    actions = [parser.OFPActionOutput(in_port)]
                    arp_reply = packet.Packet()

                    arp_reply.add_protocol(ethernet.ethernet(
                        ethertype=eth.ethertype,
                        dst=eth_src,
                        src=self.switch_adds[(self.nat_switch_id, self.nat_switch_port)]))

                    # add arp protocol
                    arp_reply.add_protocol(arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=self.switch_adds[(self.nat_switch_id, self.nat_switch_port)],
                        src_ip=arp_dst_ip,
                        dst_mac=eth_src,
                        dst_ip=arp_src_ip))

                    # serialize the packet to binary format 0101010101
                    arp_reply.serialize()
                    # arp reply
                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=ofproto.OFPP_CONTROLLER,
                        actions=actions, data=arp_reply.data)
                    datapath.send_msg(out)
                    return

                if arp_dst_ip in self.arp_table:
                    # send arp reply from in port
                    actions = [parser.OFPActionOutput(in_port)]
                    arp_reply = packet.Packet()

                    arp_reply.add_protocol(ethernet.ethernet(
                        ethertype=eth.ethertype,
                        dst=eth_src,
                        src=self.arp_table[arp_dst_ip][0]))

                    arp_reply.add_protocol(arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=self.arp_table[arp_dst_ip][0],
                        src_ip=arp_dst_ip,
                        dst_mac=eth_src,
                        dst_ip=arp_src_ip))
                    # serialize the packet to binary format 0101010101
                    arp_reply.serialize()
                    # arp reply
                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=ofproto.OFPP_CONTROLLER,
                        actions=actions, data=arp_reply.data)
                    datapath.send_msg(out)
                    return

                elif in_port!=self.nat_switch_port or datapath.id != self.nat_switch_id :
                    # send arp reply from in port
                    actions = [parser.OFPActionOutput(in_port)]
                    arp_reply = packet.Packet()

                    arp_reply.add_protocol(ethernet.ethernet(
                        ethertype=eth.ethertype,
                        dst=eth_src,
                        src=self.switch_adds[(datapath.id, in_port)]))

                    # add arp protocol
                    arp_reply.add_protocol(arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=self.switch_adds[(datapath.id, in_port)],
                        src_ip=arp_dst_ip,
                        dst_mac=eth_src,
                        dst_ip=arp_src_ip))

                    # serialize the packet to binary format 0101010101
                    arp_reply.serialize()
                    # arp reply
                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=ofproto.OFPP_CONTROLLER,
                        actions=actions, data=arp_reply.data)
                    datapath.send_msg(out)
                    return

    def default_handler(self, curr_switch, in_port, src_ip, dst_ip, msg):
        # 寻路并转发，要修改mac
        dst_mac, dst_switch, final_port = self.arp_table[dst_ip]
        self.logger.info(
            "Origin Packet dst_mac is {}".format(packet.Packet(msg.data).get_protocols(ethernet.ethernet)[0].dst))
        # 修改报文目的MAC
        self.logger.info(
            "I want to change dst_mac to {}".format(dst_mac))

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        eth.dst = dst_mac
        pkt.serialize()
        msg.data = pkt.data
        self.logger.info(
            "After changed dst_mac is {}".format(packet.Packet(msg.data).get_protocols(ethernet.ethernet)[0].dst))
        self.send_packet(curr_switch, in_port, src_ip, dst_ip, msg, dst_mac, dst_switch, final_port)

    def send_packet(self, curr_switch, in_port, src_ip, dst_ip, msg, dst_mac=None, dst_switch=None, final_port=None,
                    src_mac=None):
        datapath = msg.datapath
        # object for the negotiated Openflow version
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # 找到源和目的主机的mac及连接的虚拟机
        # print(dst_switch)
        # print(final_port)
        # print(dst_mac)
        if dst_switch is None or final_port is None or dst_mac is None:
            dst_mac, dst_switch, final_port = self.arp_table[dst_ip]
        if src_mac is None:
            src_mac, _, _ = self.arp_table[src_ip]
        # src_mac, curr_switch, in_port = self.arp_table[src_ip]
        shortest_path, sp = self.topo.shortest_path(
            curr_switch,
            dst_switch,
            in_port,
            final_port)
        self.logger.info(
            "The shortest path from {} to {} contains {} switches".format(src_ip, dst_ip, len(shortest_path)))
        assert len(shortest_path) > 0

        # log the shortest path
        path_str = ''

        # (s1,inport,outport)->(s2,inport,outport)->...->(dest_switch,inport,outport)
        for s, ip, op in shortest_path:
            path_str = path_str + "--{}-{}-{}--".format(ip, s, op)

        self.logger.info("The shortset path from {} to {} is {}".format(curr_switch, dst_switch, path_str))

        self.logger.info("Have calculated the shortest path from {} to {}".format(curr_switch, dst_switch))

        self.logger.info("Now configuring switches of interest")
        self.configure_path(shortest_path, msg, src_mac, dst_mac)
        self.logger.info("Configure done")
        out_port = None
        for s, _, op in shortest_path:
            # print(s,dpid)
            if s == curr_switch:
                out_port = op
        if out_port is None:
            return
        actions = [parser.OFPActionOutput(out_port)]
        data = None

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        # send the packet out to avoid packet loss
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

    # 查寻发送
    def find(self, IP):
        if IP in self.arp_table:
            return True
        else:
            return False

    # 查寻发送
    def find_send(self):
        for i in range(len(self.buffer) - 1, -1, -1):
            self.logger.info(
                "Find a packet in buffer can be sent from {} to {}".format(self.buffer[i][0], self.buffer[i][1]))
            curr_switch = self.buffer[i][3].datapath.id
            in_port = self.buffer[i][3].match['in_port']
            if self.buffer[i][0] in self.arp_table and self.buffer[i][1] in self.arp_table:
                if self.buffer[i][1] == self.net_getaway_ip:
                    pkt = packet.Packet(self.buffer[i][3].data)
                    eth = pkt.get_protocols(ethernet.ethernet)[0]
                    parser = self.nat_switch.dp.ofproto_parser
                    pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
                    pkt_icmp = pkt.get_protocol(icmp.icmp)
                    pkt_tcp = pkt.get_protocol(tcp.tcp)
                    pkt_udp = pkt.get_protocol(udp.udp)
                    src_ip = copy.copy(pkt_ipv4.src)

                    # 修改mac
                    eth.dst = self.arp_table[self.net_getaway_ip][0]
                    # 修改原ip
                    pkt_ipv4.src = self.nat_ip

                    if pkt_icmp:
                        # 修改id
                        pkt_icmp.data.id = self.icmp_out[(src_ip, pkt_icmp.data.id)]
                        self.ICMPTTLinit(pkt_icmp.data.id)
                        pkt_icmp.csum = 0
                    elif pkt_tcp:
                        # 修改id
                        pkt_tcp.src_port = self.tcp_out[(src_ip, pkt_tcp.src_port)]
                        pkt_tcp.csum = 0
                    elif pkt_udp:
                        # 修改id
                        pkt_udp.src_port = self.udp_out[(src_ip, pkt_udp.src_port)]
                        pkt_udp.csum = 0

                    self.logger.info(
                        "changed_ip is from {} to {}".format(src_ip, pkt_ipv4.src))

                    pkt.serialize()

                    actions = [parser.OFPActionOutput(self.nat_switch_port)]
                    self.send_out(self.nat_switch, actions, pkt.data)
                    # out = parser.OFPPacketOut(
                    #     datapath=self.nat_switch.dp,
                    #     buffer_id=self.nat_switch.dp.ofproto.OFP_NO_BUFFER,
                    #     in_port=self.nat_switch.dp.ofproto.OFPP_CONTROLLER,
                    #     actions=actions, data=pkt.data)
                    self.logger.info("  {} to {}".format(pkt_ipv4.src, self.net_getaway_ip))
                    # self.nat_switch.dp.send_msg(out)
                else:
                    self.default_handler(curr_switch, in_port, self.buffer[i][0], self.buffer[i][1], self.buffer[i][3])
                self.buffer.pop(i)

    # 存储并发送arp
    def stor(self, msg):
        # msg = ev.msg
        datapath = msg.datapath
        port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        if not pkt_ethernet:
            return
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        eth_dst = eth.dst
        eth_src = eth.src
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        # src ip
        src_ip = copy.copy(pkt_ipv4.src)
        # dst ip
        dst_ip = copy.copy(pkt_ipv4.dst)
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # 不在私网内
        if not self.ipInSubnet(dst_ip, self.net_ip) and not self.ipInSubnet(pkt_ipv4.dst, "/".join((self.nat_ip, self.nat_mask))):
            #修改原ip
            dst_ip = self.net_getaway_ip

        # 存储报文
        self.buffer.append([src_ip, dst_ip, 20, msg])

        # 发送arp
        for s, port_no in self.edge_switch:
            if s.dp.id == datapath.id and port == port_no:
                continue
            self.logger.info("Send ARP in edge_switch:{}  port:{}".format(s.dp.id, port_no))

            actions = [parser.OFPActionOutput(port_no)]
            arp_send = packet.Packet()

            arp_send.add_protocol(ethernet.ethernet(
                ethertype=2054,
                dst="ff:ff:ff:ff:ff:ff",
                src=eth_src))

            # add arp protocol
            arp_send.add_protocol(arp.arp(
                opcode=arp.ARP_REQUEST,
                src_mac=eth_src,
                src_ip=src_ip,
                dst_mac="00:00:00:00:00:00",
                dst_ip=dst_ip))

            # serialize the packet to binary format 0101010101
            arp_send.serialize()
            # arp reply
            out = parser.OFPPacketOut(
                datapath=s.dp,
                buffer_id=s.dp.ofproto.OFP_NO_BUFFER,
                in_port=s.dp.ofproto.OFPP_CONTROLLER,
                actions=actions, data=arp_send.data)
            s.dp.send_msg(out)

    # 生命周期减少
    def TTLdes(self):
        for i in range(len(self.buffer) - 1, -1, -1):
            self.buffer[i][2] -= 1
            if self.buffer[i][2] <= 0:
                self.buffer.pop(i)

        # 添加padding

    def ICMPTTLdes(self):
        # 来个icmp报文就便利寿命减一
        for key in list(self.icmp_life.keys()):
            self.icmp_life[key] -= 1
            if self.icmp_life[key] <= 0:
                temp = self.icmp_in[key]
                self.icmp_out.pop(temp)
                self.icmp_in.pop(key)
                self.icmp_life.pop(key)
                continue

    def ICMPTTLinit(self, key):
        self.icmp_life[key] = 5

    def NAT_in(self, msg):
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        parser = self.nat_switch.dp.ofproto_parser
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_udp = pkt.get_protocol(udp.udp)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_icmp = pkt.get_protocol(icmp.icmp)

        # icmp
        if pkt_icmp and pkt_icmp.type == icmp.ICMP_ECHO_REPLY:
            # 找到icmp未有记录
            if pkt_icmp.data.id in self.icmp_in:

                # 来个icmp报文就便利寿命减一
                self.ICMPTTLdes()

                self.logger.info(
                    "----------------Received a packet to our network from internet , src_ip: {}   -----------------------------".format(
                        pkt_ipv4.src))
                pkt_ipv4.dst = self.icmp_in[pkt_icmp.data.id][0]
                pkt_icmp.data.id = self.icmp_in[pkt_icmp.data.id][1]
                pkt_icmp.csum = 0
                print("Change origin dst IP to {}".format(pkt_ipv4.dst))

                # 找出在一个子网的有主机边缘交换机及mac
                if self.find(pkt_ipv4.dst):
                    dst_mac, dst_switch_id, final_port = self.arp_table[pkt_ipv4.dst]
                    print("find switch {} port {} ".format(dst_switch_id, final_port))
                    eth.dst = dst_mac
                    pkt.serialize()
                    actions = [parser.OFPActionOutput(final_port)]
                    msg.data = pkt.data
                    dst_switch = copy.copy(get_switch(self, dst_switch_id))[0]
                    out = parser.OFPPacketOut(
                        datapath=dst_switch.dp,
                        buffer_id=dst_switch.dp.ofproto.OFP_NO_BUFFER,
                        in_port=dst_switch.dp.ofproto.OFPP_CONTROLLER,
                        actions=actions, data=pkt.data)
                    dst_switch.dp.send_msg(out)
                else:
                    self.stor(msg)
        # tcp
        elif pkt_tcp:
            # 找到tcpp未有记录
            if pkt_tcp.dst_port in self.tcp_in:
                self.logger.info(
                    "----------------Received a packet to our network from internet , src_ip: {}   -----------------------------".format(
                        pkt_ipv4.src))
                pkt_ipv4.dst = self.tcp_in[pkt_tcp.dst_port][0]
                pkt_tcp.dst_port = self.tcp_in[pkt_tcp.dst_port][1]
                pkt_tcp.csum = 0
                print("Change origin dst IP to {}".format(pkt_ipv4.dst))

                # 找出在一个子网的有主机边缘交换机及mac
                if self.find(pkt_ipv4.dst):
                    dst_mac, dst_switch_id, final_port = self.arp_table[pkt_ipv4.dst]
                    print("find switch {} port {} ".format(dst_switch_id, final_port))
                    eth.dst = dst_mac
                    pkt.serialize()
                    actions = [parser.OFPActionOutput(final_port)]
                    msg.data = pkt.data
                    dst_switch = copy.copy(get_switch(self, dst_switch_id))[0]
                    out = parser.OFPPacketOut(
                        datapath=dst_switch.dp,
                        buffer_id=dst_switch.dp.ofproto.OFP_NO_BUFFER,
                        in_port=dst_switch.dp.ofproto.OFPP_CONTROLLER,
                        actions=actions, data=pkt.data)
                    dst_switch.dp.send_msg(out)
                else:
                    self.stor(msg)


        # udp
        elif pkt_udp:
            # 找到udp未有记录
            if pkt_udp.dst_port in self.udp_in:
                self.logger.info(
                    "----------------Received a packet to our network from internet , src_ip: {}   -----------------------------".format(
                        pkt_ipv4.src))
                pkt_ipv4.dst = self.udp_in[pkt_udp.dst_port][0]
                pkt_udp.dst_port = self.udp_in[pkt_udp.dst_port][1]
                pkt_udp.csum = 0
                print("Change origin dst IP to {}".format(pkt_ipv4.dst))

                # 找出在一个子网的有主机边缘交换机及mac
                if self.find(pkt_ipv4.dst):
                    dst_mac, dst_switch_id, final_port = self.arp_table[pkt_ipv4.dst]
                    print("find switch {} port {} ".format(dst_switch_id, final_port))
                    eth.dst = dst_mac
                    pkt.serialize()
                    actions = [parser.OFPActionOutput(final_port)]
                    msg.data = pkt.data
                    dst_switch = copy.copy(get_switch(self, dst_switch_id))[0]
                    out = parser.OFPPacketOut(
                        datapath=dst_switch.dp,
                        buffer_id=dst_switch.dp.ofproto.OFP_NO_BUFFER,
                        in_port=dst_switch.dp.ofproto.OFPP_CONTROLLER,
                        actions=actions, data=pkt.data)
                    dst_switch.dp.send_msg(out)
                else:
                    self.stor(msg)

    def NAT_out(self, msg):
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        parser = self.nat_switch.dp.ofproto_parser
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_udp = pkt.get_protocol(udp.udp)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_icmp = pkt.get_protocol(icmp.icmp)

        if pkt_icmp and pkt_icmp.type == icmp.ICMP_ECHO_REQUEST:
            # 找到icmp未有记录
            if (pkt_ipv4.src, pkt_icmp.data.id) not in self.icmp_out:
                icmp_id = copy.copy(pkt_icmp.data.id)
                # 使得变换后icmp不冲突
                while icmp_id in self.icmp_in:
                    icmp_id += 1

                self.icmp_out[(pkt_ipv4.src, pkt_icmp.data.id)] = icmp_id
                self.icmp_in[icmp_id] = (pkt_ipv4.src, pkt_icmp.data.id)
                self.ICMPTTLinit(icmp_id)

            src_ip = copy.copy(pkt_ipv4.src)
            actions = [parser.OFPActionOutput(self.nat_switch_port)]

            # 修改mac
            if self.net_getaway_ip in self.arp_table and  not self.ipInSubnet(pkt_ipv4.dst , "/".join((self.nat_ip,self.nat_mask))):
                eth.dst = self.arp_table[self.net_getaway_ip][0]
            elif  pkt_ipv4.dst in self.arp_table:
                eth.dst = self.arp_table[pkt_ipv4.dst][0]
            else:
                self.stor(msg)

                return
            # 修改id
            pkt_icmp.data.id = self.icmp_out[(src_ip, pkt_icmp.data.id)]
            self.ICMPTTLinit(pkt_icmp.data.id)
            # 修改原ip
            pkt_ipv4.src = self.nat_ip
            self.logger.info(
                "send to internet changed_ip is from {} to {}".format(src_ip, pkt_ipv4.src))
            pkt_icmp.csum = 0
            pkt.serialize()
            self.send_out(self.nat_switch, actions, pkt.data)



        elif pkt_tcp:
            # 找到icmp未有记录
            if (pkt_ipv4.src, pkt_tcp.src_port) not in self.tcp_out:
                src_port = copy.copy(pkt_tcp.src_port)
                # 使得变换后icmp不冲突
                while src_port in self.tcp_in:
                    src_port += 1

                self.tcp_out[(pkt_ipv4.src, pkt_tcp.src_port)] = src_port
                self.tcp_in[src_port] = (pkt_ipv4.src, pkt_tcp.src_port)

            src_ip = copy.copy(pkt_ipv4.src)
            actions = [parser.OFPActionOutput(self.nat_switch_port)]

            # 修改mac
            if self.net_getaway_ip in self.arp_table and  not self.ipInSubnet(pkt_ipv4.dst , "/".join((self.nat_ip,self.nat_mask))):
                eth.dst = self.arp_table[self.net_getaway_ip][0]
            elif  pkt_ipv4.dst in self.arp_table:
                eth.dst = self.arp_table[pkt_ipv4.dst][0]
            else:
                self.stor(msg)

                return

            # 修改port
            pkt_tcp.src_port = self.tcp_out[(src_ip, pkt_tcp.src_port)]
            # 修改原ip
            pkt_ipv4.src = self.nat_ip
            self.logger.info(
                "send to internet changed_ip is from {} to {}".format(src_ip, pkt_ipv4.src))
            pkt_tcp.csum = 0
            pkt.serialize()
            self.send_out(self.nat_switch, actions, pkt.data)

        elif pkt_udp:
            # 找到icmp未有记录
            if (pkt_ipv4.src, pkt_udp.src_port) not in self.udp_out:
                src_port = copy.copy(pkt_udp.src_port)
                # 使得变换后icmp不冲突
                while src_port in self.udp_in:
                    src_port += 1

                self.udp_out[(pkt_ipv4.src, pkt_udp.src_port)] = src_port
                self.udp_in[src_port] = (pkt_ipv4.src, pkt_udp.src_port)

            src_ip = copy.copy(pkt_ipv4.src)
            actions = [parser.OFPActionOutput(self.nat_switch_port)]

            # 修改mac
            if self.net_getaway_ip in self.arp_table and  not self.ipInSubnet(pkt_ipv4.dst , "/".join((self.nat_ip,self.nat_mask))):
                eth.dst = self.arp_table[self.net_getaway_ip][0]
            elif  pkt_ipv4.dst in self.arp_table:
                eth.dst = self.arp_table[pkt_ipv4.dst][0]
            else:
                self.stor(msg)

                return

            # 修改id
            pkt_udp.src_port = self.udp_out[(src_ip, pkt_udp.src_port)]
            # 修改原ip
            pkt_ipv4.src = self.nat_ip
            self.logger.info(
                "send to internet changed_ip is from {} to {}".format(src_ip, pkt_ipv4.src))
            pkt_udp.csum = 0
            pkt.serialize()
            self.send_out(self.nat_switch, actions, pkt.data)

    @staticmethod
    def send_out(switch, actions, data):
        parser = switch.dp.ofproto_parser
        out = parser.OFPPacketOut(
            datapath=switch.dp,
            buffer_id=switch.dp.ofproto.OFP_NO_BUFFER,
            in_port=switch.dp.ofproto.OFPP_CONTROLLER,
            actions=actions, data=data)
        switch.dp.send_msg(out)

    # 添加padding
    def addPadding(self, length):
        return binascii.unhexlify("00" * length)

    def ipINvpn(self,ip):
        for net in self.vpn_net:
            if self.ipInSubnet(ip,net):
                return True
        return  False

    # 判断IP地址是否属于这个网段
    def ipInSubnet(self, ip, subnet):
        def ipToBinary(ip):
            '''ip address transformat into binary
            Argv:
                ip: ip address
            Return:
                binary
            '''
            ip_num = ip.split('.')
            x = 0

            ##IP地址是点分十进制，例如：192.168.1.33，共32bit
            ##第1节（192）向前移24位，第2节（168）向前移16位
            ##第3节（1）向迁移8位，第4节（33）不动
            ##然后进行或运算，得出数据
            for i in range(len(ip_num)):
                num = int(ip_num[i]) << (24 - i * 8)
                x = x | num

            brnary = str(bin(x).replace('0b', ''))
            return brnary

        ##将子网掩码转为二进制
        def maskToBinary(mask):
            '''netmask change, example: 24 or 255.255.255.0 change binary
            Argv:
                mask: netmask, example:24 or 255.255.255.0
            Return:
                binary
            '''
            mask_list = str(mask).split('.')

            ##子网掩码有两种表现形式，例如：/24或255.255.255.0
            if len(mask_list) == 1:
                ##生成一个32个元素均是0的列表
                binary32 = []
                for i in range(32):
                    binary32.append('0')

                ##多少位子网掩码就是连续多少个1
                for i in range(int(mask)):
                    binary32[i] = '1'

                binary = ''.join(binary32)

            ##输入的子网掩码是255.255.255.0这种点分十进制格式
            elif len(mask_list) == 4:
                binary = ipToBinary(mask)

            return binary

        '''
        Argv:
            ip: ip address,example:1.1.1.1
            subnet: subnet,example:1.1.1.0/24,or 1.1.1.0/255.255.255.0
        Return:
            False or True
        '''
        subnet_list = subnet.split('/')
        networt_add = subnet_list[0]
        network_mask = subnet_list[1]

        ##原来的得出的二进制数据类型是str，转换数据类型
        ip_num = int(ipToBinary(ip), 2)
        subnet_num = int(ipToBinary(networt_add), 2)
        mask_bin = int(maskToBinary(network_mask), 2)

        ##IP和掩码与运算后比较
        if (ip_num & mask_bin) == (subnet_num & mask_bin):
            return True
        else:
            return False

