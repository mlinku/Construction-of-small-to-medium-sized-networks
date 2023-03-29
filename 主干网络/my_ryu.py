import binascii
import copy
import math
import random
from collections import defaultdict
from operator import attrgetter

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib import mac, ofctl_v1_3
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4, ipv6, dhcp, udp, tcp, icmp, ether_types, in_proto
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_v1_3, ether, inet
from ryu.ofproto.ofproto_v1_3 import OFPP_IN_PORT
from ryu.topology import event
from ryu.topology.api import get_switch, get_link

from CircleBucket import CircleBucket


class Topo(object):
    def __init__(self, logger):
        self.adjacent = defaultdict(lambda s1s2: None)
        # datapathes
        self.switches = None
        self.host_mac_to = {}
        self.logger = logger
        self.max_weight = 100
        self.update_times = 0
        self.host = None

    def init(self):
        self.adjacent = defaultdict(lambda s1s2: None)
        self.switches = None
        self.host_mac_to = {}
        self.host = None

    def reset(self):
        self.adjacent = defaultdict(lambda s1s2: None)
        self.switches = None
        self.host_mac_to = None

    # def get_adjacent(self, s1, s2):
    #     return self.adjacent.get((s1, s2))
    #
    # def set_adjacent(self, s1, s2, port, weight=1, traffic=0):
    #     self.adjacent[(s1, s2)] = port
    #     # self.adjacent[(s1, s2)] = [port, weight, cycle_traffic ,all_traffic]
    def find_adjacent(self, s1, s2):
        if s1 in self.adjacent and s2 in self.adjacent[s1]:
            return True
        else:
            return False

    def get_adjacent(self, s1):
        return self.adjacent[s1]

    def set_adjacent(self, s1, s2, port, weight=1, cycle_traffic=0, all_traffic=0):
        if s1 not in self.adjacent.keys():
            self.adjacent[s1] = {}
        self.adjacent[s1][s2] = [port, weight, cycle_traffic, all_traffic]

    def update_adjacent(self, s1, s2, port=None, weight=None, cycle_traffic=None, all_traffic=None):
        if port:
            self.adjacent[s1][s2][0] = port
        if weight:
            self.adjacent[s1][s2][1] = weight
        if cycle_traffic:
            self.adjacent[s1][s2][2] = cycle_traffic
        if all_traffic:
            self.adjacent[s1][s2][3] = all_traffic

    def update_weight(self):
        all_traffic = [list(edge.values()) for edge in self.adjacent.values()]
        max_cycle_traffic = max([max(i, key=lambda item: item[2])[2] for i in all_traffic])
        min_cycle_traffic = min([min(i, key=lambda item: item[2])[2] for i in all_traffic])
        self.update_times += 1
        for s1, data in self.adjacent.items():
            for s2, [_, _, cycle_traffic, _] in data.items():
                # 计算权重并更新
                weight = math.ceil(((cycle_traffic - min_cycle_traffic) * 100 / (
                        max_cycle_traffic - min_cycle_traffic) if max_cycle_traffic != min_cycle_traffic and cycle_traffic != min_cycle_traffic else 1) )
                self.update_adjacent(s1, s2, weight=weight)
        if self.update_times % len(self.switches) ==0:
            self.print_weight()

    def print_weight(self):
        print("\n---------------------update weight---------------------")
        for s1, data in self.adjacent.items():
            print("{}: ".format(s1),end=" ")
            for s2, [_, weight, _, _] in data.items():
                print("{}-{} weight:{}".format(s1, s2, weight),end="  ")
            print("\n")

    @staticmethod
    def printPath(path):
        for sw in path:
            print(sw, "-", end=' ')  # [(3,1,[3't'# ]),(4,2,[1])]
        print("end")

    def Dijkstra(self, src_sw, dst_sw, src_port, dst_port):
        # print("now we begin to find the shortest paths from sw:{} port:{} to sw:{} port:{} ".format(src_sw, src_port,
        #                                                                                             dst_sw,
        #                                                                                             dst_port))
        bucket = CircleBucket(self.max_weight + 1)  # 创建循环桶对象
        bucket.updateBucket(0, src_sw)  # 将源点先加入桶
        # pre用于存储路径 并将所有交换机在路径的前置结点初始化为None
        pre = {}
        # dis用于存储距离 并将所有交换机离源交换机距离初始化为9999999
        dis = {}
        for sw in self.switches:
            pre[sw] = None
            dis[sw] = 9999999
        dis[src_sw] = 0  # 将源结点的距离初始化为0
        flag = 1  # flag 用于判断是否找到目的交换机 因为这是一个单源单宿问题
        while flag == 1 and not bucket.checkBucketEmpty():  # 若还没找到目的交换机或桶内结点数不为空则继续循环
            sw = bucket.getFirst()  # 取出现在离源交换机最近的交换机
            if sw == dst_sw:  # 判断取出的交换机是不是目的交换机 如果是将flag置0并退出循环
                flag = 0
                break
            for u in self.switches:
                if u in (self.get_adjacent(sw)).keys():
                    # print(self.get_Adjdict(sw)[u])
                    # 遍历取出交换机的所有邻接交换机 并更新循环桶内数据
                    if dis[sw] + self.get_adjacent(sw)[u][1] < dis[u]:  # 判断邻接交换机离源交换机的距离有没有缩短
                        dis[u] = dis[sw] + self.get_adjacent(sw)[u][1]
                        pre[u] = sw  # 设置前置交换机
                        bucket.updateBucket(dis[u], u)  # 将桶数据数据更新
        spath = [dst_sw]
        sw = dst_sw
        while pre[sw] != None:  # 通过pre找出最短路径
            sw = pre[sw]
            spath.append(sw)
        spath.reverse()  # 将路径反转为从到源交换机到目的交换机
        # print("Find done.The shortest path :", end=" ")
        # self.printPath(spath)  # 输出最短路径

        # 现在我们已经通过Dijkstra算法找到最短路径了，接下来把该路径转化为控制器配置的格式
        # 交换机之间路径的配置格式如右 (src_sw,inport,outport)->.......->(dst_sw,inport,outport) 我们要把所有路经的交换机都记录为左边的格式
        cpath = []  # configure path
        inport = src_port
        for i in range(len(spath) - 1):
            s1 = spath[i]
            s2 = spath[i + 1]
            # get s1->s2 outport
            outport = self.get_adjacent(s1)[s2][0]
            cpath.append((s1, inport, outport))
            inport = self.get_adjacent(s2)[s1][0]
        cpath.append((dst_sw, inport, dst_port))
        # return cpath can configure switch's path  返回可以配置的路径
        return cpath


# TODO Port status monitor

class Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)
        self.ofctl = ofctl_v1_3
        self.mac_to_port = {}
        self.waiters = {}
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
        self.all_switches = []
        self.all_links = {}
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
        self.dhcp_ip = []
        self.dhcp_switch = None
        self.dhcp_relay = []
        self.dhcp_link_stats = []

        # 服务器主机及映射
        self.serve_host = None

        # VPN网络
        self.vpn_net = []
        self.read_information()

        # 流量监控
        self.monitor_thread = hub.spawn(self._monitor)
        # 请求交换机状态周期
        self.monitor_time = 10
        # 流表过期周期
        self.hard_timeout = 10

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

            # 读取DHCP IP地址
            self.dhcp_ip = content[6].replace('\n', '').replace(' ', '').split('=')[-1].split(';')

            print("-----------------------DHCP_IP:  {}---------------------".format(self.dhcp_ip))

            # 读取DHCP switch 相关信息
            self.dhcp_switch = int(content[7].replace('\n', '').replace(' ', '').split('=')[-1])

            print("-----------------------DHCP_Switch:  {}---------------------".format(self.dhcp_switch))

            # 读取DHCP 中继相关信息
            dhcp_relay_str = content[8].replace('\n', '').replace(' ', '').split('=')[-1]
            for item in dhcp_relay_str.split(';'):
                self.dhcp_relay.append((int(item.split(',')[0]), int(item.split(',')[1]), item.split(',')[2]))
            print("-----------------------DHCP_Relay:  {}---------------------".format(self.dhcp_relay))

            # 读取web 相关信息
            self.serve_host = content[9].replace('\n', '').replace(' ', '').split('=')[-1].split(';')
            for host in self.serve_host:
                self.tcp_out[(host.split(',')[0].split(':')[0], int(host.split(',')[0].split(':')[1]))] = int(
                    host.split(',')[1])
                self.tcp_in[int(host.split(',')[1])] = (
                    host.split(',')[0].split(':')[0], int(host.split(',')[0].split(':')[1]))
            print("-----------------------server_host:  {}---------------------".format(self.serve_host))

            # 读取VPN网络信息
            self.vpn_net = content[10].replace('\n', '').replace(' ', '').split('=')[-1].split(';')
            print("-----------------------vpn_net:  {}---------------------".format(self.vpn_net))

            print(self.tcp_out)
            print(self.tcp_in)

    def _find_dp(self, dpid):
        for dp in self.datapaths:
            if dp.id == dpid:
                return dp
        return None

    def _monitor(self):
        while True:
            for s in self.all_switches:
                self._request_stats(s.dp)
            hub.sleep(self.monitor_time)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: {}'.format(datapath.id))
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        # 更新流量差和全流量
        # print(self.all_links)
        for stat in sorted(body, key=attrgetter('port_no')):
            if (ev.msg.datapath.id, stat.port_no) in self.all_links:
                # 计算流量差
                traffic_sub = stat.rx_bytes - self.topo.get_adjacent(ev.msg.datapath.id)[
                    self.all_links[(ev.msg.datapath.id, stat.port_no)][0]][3]
                self.topo.update_adjacent(ev.msg.datapath.id, self.all_links[(ev.msg.datapath.id, stat.port_no)][0],
                                          cycle_traffic=traffic_sub, all_traffic=stat.rx_bytes)
        # 更新完后更新权重
        self.topo.update_weight()
        # self.logger.info(' {}  {}  {}  {}'.format(ev.msg.datapath.id, stat.port_no,stat.rx_packets, stat.rx_bytes))
        # print(self.topo.adjacent)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    def configure_path(self, shortest_path, msg, origin_mac, dst_mac, dst_ip):
        # configure shortest path to switches
        recv_datapath = msg.datapath
        for switch, inport, outport in shortest_path:
            flow_list = []
            datapath = self._find_dp(int(switch))
            actions = [datapath.ofproto_parser.OFPActionOutput(outport)]
            # 目的IP为外网报文
            # 第一个交换机
            pkt = packet.Packet(msg.data)
            pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
            if int(switch) == recv_datapath.id:
                if dst_ip == self.nat_ip:


                    pkt_tcp = pkt.get_protocol(tcp.tcp)
                    pkt_udp = pkt.get_protocol(udp.udp)
                    if pkt_tcp:
                        tcp_match = datapath.ofproto_parser.OFPMatch(in_port=inport, ipv4_dst=dst_ip,
                                                                     tcp_dst=pkt_tcp.dst_port,
                                                                     eth_type=ether_types.ETH_TYPE_IP,
                                                                     ip_proto=in_proto.IPPROTO_TCP)
                        tcp_actions = [datapath.ofproto_parser.OFPActionSetField(
                            ipv4_dst=self.tcp_in[pkt_tcp.dst_port][0]), datapath.ofproto_parser.OFPActionSetField(
                            tcp_dst=self.tcp_in[pkt_tcp.dst_port][1]),
                                          datapath.ofproto_parser.OFPActionSetField(eth_dst=dst_mac)] + actions
                        dst_ip = self.tcp_in[pkt_tcp.dst_port][0]

                        flow_list.append((tcp_actions, tcp_match))

                    if pkt_udp:
                        udp_match = datapath.ofproto_parser.OFPMatch(in_port=inport, ipv4_dst=dst_ip,

                                                                     udp_dst=pkt_udp.dst_port,
                                                                     eth_type=ether_types.ETH_TYPE_IP,
                                                                     ip_proto=in_proto.IPPROTO_UDP)

                        udp_actions = [datapath.ofproto_parser.OFPActionSetField(
                            ipv4_dst=self.udp_in[pkt_udp.dst_port][0]), datapath.ofproto_parser.OFPActionSetField(
                            udp_dst=self.udp_in[pkt_udp.dst_port][1]),
                                          datapath.ofproto_parser.OFPActionSetField(eth_dst=dst_mac)] + actions
                        dst_ip = self.udp_in[pkt_udp.dst_port][0]
                        # print(self.udp_in)
                        # print(self.udp_out)
                        flow_list.append((udp_actions, udp_match))
                elif int(switch) == self.nat_switch_id and not self.ipINvpn(pkt_ipv4.dst, msg.match['in_port'], datapath.id):

                    pkt_tcp = pkt.get_protocol(tcp.tcp)
                    pkt_udp = pkt.get_protocol(udp.udp)
                    if pkt_tcp:
                        tcp_match = datapath.ofproto_parser.OFPMatch(in_port=inport, ipv4_src=pkt_ipv4.src,
                                                                     tcp_src=pkt_tcp.src_port, ipv4_dst=dst_ip,
                                                                     eth_type=ether_types.ETH_TYPE_IP,
                                                                     ip_proto=in_proto.IPPROTO_TCP)
                        tcp_actions = [datapath.ofproto_parser.OFPActionSetField(ipv4_src=self.nat_ip),
                                       datapath.ofproto_parser.OFPActionSetField(
                                           tcp_src=self.tcp_out[(pkt_ipv4.src, pkt_tcp.src_port)])] + actions
                        flow_list.append((tcp_actions, tcp_match))

                    if pkt_udp:
                        udp_match = datapath.ofproto_parser.OFPMatch(in_port=inport, ipv4_src=pkt_ipv4.src,
                                                                     udp_src=pkt_udp.src_port, ipv4_dst=dst_ip,
                                                                     eth_type=ether_types.ETH_TYPE_IP,
                                                                     ip_proto=in_proto.IPPROTO_UDP)
                        udp_actions = [datapath.ofproto_parser.OFPActionSetField(ipv4_src=self.nat_ip),
                                       datapath.ofproto_parser.OFPActionSetField(
                                           udp_src=self.udp_out[(pkt_ipv4.src, pkt_udp.src_port)])] + actions
                        flow_list.append((udp_actions, udp_match))
                else:

                    match = datapath.ofproto_parser.OFPMatch(in_port=inport, eth_dst=origin_mac, ipv4_dst=dst_ip,
                                                             eth_type=ether_types.ETH_TYPE_IP)
                    actions.insert(0, datapath.ofproto_parser.OFPActionSetField(eth_dst=dst_mac))
                    flow_list.append((actions, match))
                # 从nat收到且不为隧道
                # if int(switch) == self.nat_switch_id and inport == self.nat_switch_port and not self.ipInSubnet(packet.Packet(msg.data).get_protocol(ipv4.ipv4).src, self.net_ip)
                #     match = datapath.ofproto_parser.OFPMatch(in_port=inport, eth_dst=origin_mac, ipv4_dst=dst_ip,
                #                                              eth_type=ether_types.ETH_TYPE_IP)
                #     actions = [datapath.ofproto_parser.OFPActionSetField(eth_dst=dst_mac),
                #                datapath.ofproto_parser.OFPActionOutput(outport)]
            # match = parser.OFPMatch()
            # NAT_OUT报文 非第一个交换机
            elif not self.ipInSubnet(dst_ip, self.net_ip) :
                # 如果是nat交换机 下发更改IP和端口的流表
                if switch == self.nat_switch_id:
                    pkt_tcp = pkt.get_protocol(tcp.tcp)
                    pkt_udp = pkt.get_protocol(udp.udp)
                    if pkt_tcp:
                        tcp_match = datapath.ofproto_parser.OFPMatch(in_port=inport, ipv4_src=pkt_ipv4.src,
                                                                     tcp_src=pkt_tcp.src_port, ipv4_dst=dst_ip,
                                                                     eth_type=ether_types.ETH_TYPE_IP,
                                                                     ip_proto=in_proto.IPPROTO_TCP)
                        tcp_actions = [datapath.ofproto_parser.OFPActionSetField(ipv4_src=self.nat_ip),
                                       datapath.ofproto_parser.OFPActionSetField(
                                           tcp_src=self.tcp_out[(pkt_ipv4.src, pkt_tcp.src_port)])] + actions
                        flow_list.append((tcp_actions, tcp_match))

                    if pkt_udp:
                        udp_match = datapath.ofproto_parser.OFPMatch(in_port=inport, ipv4_src=pkt_ipv4.src,
                                                                     udp_src=pkt_udp.src_port, ipv4_dst=dst_ip,
                                                                     eth_type=ether_types.ETH_TYPE_IP,
                                                                     ip_proto=in_proto.IPPROTO_UDP)
                        udp_actions = [datapath.ofproto_parser.OFPActionSetField(ipv4_src=self.nat_ip),
                                       datapath.ofproto_parser.OFPActionSetField(
                                           udp_src=self.udp_out[(pkt_ipv4.src, pkt_udp.src_port)])] + actions
                        flow_list.append((udp_actions, udp_match))


                else:
                    match = datapath.ofproto_parser.OFPMatch(in_port=inport, eth_dst=dst_mac,
                                                             eth_type=ether_types.ETH_TYPE_IP)
                    flow_list.append((actions, match))
            else:
                match = datapath.ofproto_parser.OFPMatch(in_port=inport, ipv4_dst=dst_ip,
                                                         eth_type=ether_types.ETH_TYPE_IP)
                flow_list.append((actions, match))

            assert datapath is not None
            for actions, match in flow_list:
                self.add_flow(datapath, 1, match, actions, hard_timeout=self.hard_timeout)

            # inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            # mod = datapath.ofproto_parser.OFPFlowMod(
            #     datapath=datapath,
            #     match=match,
            #     idle_timeout=0,
            #     hard_timeout=10,
            #     priority=1,
            #     instructions=inst
            # )
            # datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, event):

        # msg is an object which desicribes the corresponding OpenFlow message
        msg = event.msg

        datapath = msg.datapath

        # object for the negotiated Openflow version

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

        # self.logger.info(
        #     "----------------Received a packet in switch:{}  port:{}   -----------------------------".format(dpid,
        #                                                                                                      in_port))

        pkt_dhcp = pkt.get_protocol(dhcp.dhcp)
        # 判断是否为dhcp报文

        if pkt_dhcp:
            if dpid != self.dhcp_switch:
                self.dhcp_relay_handler(msg)
            return
        # 判断是否为arp报文
        if arp_pkt:
            # 记录ip mac 设备号 端口号
            if arp_pkt.src_ip not in self.arp_table or self.arp_table[arp_pkt.src_ip] != (
                    src_mac, dpid, in_port) and src_mac != self.switch_adds[(self.nat_switch_id, self.nat_switch_port)]:
                self.arp_table[arp_pkt.src_ip] = (src_mac, dpid, in_port)
                # 查询发送
                self.find_send()
            self.arp_handler(msg)
            return

        else:
            # if pkt_ipv4.src not in self.arp_table
            # 发送到外网：目的为外网，且源不是
            if not self.ipInSubnet(dst_ip, self.net_ip) and self.ipInSubnet(src_ip, self.net_ip):
                # self.logger.info(
                #     "----------------Send a packet to internet, dst_ip: {}   -----------------------------".format(
                #         dst_ip))
                self.NAT_out(msg)
                return
            # 外网发送到内网：目的为外网，且源也是外网
            if not (self.ipInSubnet(src_ip, self.net_ip)):
                if dst_ip == self.nat_ip:
                    # self.logger.info( "----------------Received a packet from internet, src_ip: {}
                    # -----------------------------".format( src_ip)) 进入nat入函数
                    self.NAT_in(msg)
                return

            # 查询到目的IP在ARP表中
            if self.find(dst_ip):
                # self.handler()
                self.default_handler(dpid, in_port, src_ip, dst_ip, msg)
            # 未查询到结果
            else:
                self.stor(msg)

    @set_ev_cls(event.EventLinkAdd)
    def _link_add_handler(self, event):
        self.logger.info("!!!A link add.Topology rediscovery...")
        self.switch_status_handler(event, 'add')

    @set_ev_cls(event.EventLinkDelete)
    def _link_delete_handler(self, event):
        self.logger.info("!!!A link leaved.Topology rediscovery...")
        self.switch_status_handler(event, 'dele')
        self.dele_flow(event)

    def dele_flow(self, event):
        for s in self.all_switches:
            datapath = s.dp
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP)
            mod = parser.OFPFlowMod(datapath=datapath,
                                    command=ofproto.OFPFC_DELETE,
                                    out_port=ofproto.OFPP_ANY,
                                    out_group=ofproto.OFPG_ANY,
                                    match=match)
            datapath.send_msg(mod)

    # @set_ev_cls(event.EventSwitchEnter)
    # def switch_enter_handler(self, event):
    #     self.logger.info("A switch entered.Topology rediscovery...")
    #     self.switch_status_handler(event)
    #     # 多调用几次，防止ryu未检测出全部link
    #     self.logger.info('Topology rediscovery done')
    #
    # @set_ev_cls(event.EventSwitchLeave)
    # def switch_leave_handler(self, event):
    #     self.logger.info("A switch leaved.Topology rediscovery...")
    #     self.switch_status_handler(event)
    #     self.logger.info('Topology rediscovery done')

    def switch_status_handler(self, event, type):
        if type == 'dele':
            self.topo.init()
        elif type == 'add':
            pass

        all_switches = copy.copy(get_switch(self, None))
        self.all_switches = all_switches
        # 获取交换机的端口地址
        self.switch_adds = {}
        for s in all_switches:
            for port in s.ports:
                self.switch_adds[(s.dp.id, port.port_no)] = port.hw_addr
        self.nat_switch = copy.copy(get_switch(self, self.nat_switch_id))[0]
        self.logger.info('-----------------------------nat switch is: {}----------------'.format(self.nat_switch.dp.id))

        # get all datapathid
        # 获取交换机的ID值
        self.topo.switches = [s.dp.id for s in all_switches]

        self.logger.info("switches {}".format(self.topo.switches))

        self.datapaths = [s.dp for s in all_switches]

        # get link and get port

        all_link_stats = [(l.src.dpid, l.dst.dpid, l.src.port_no, l.dst.port_no) for l in
                          copy.copy(get_link(self, None))]
        self.all_links = dict(
            [[(l.src.dpid, l.src.port_no), [l.dst.dpid, l.dst.port_no]] for l in copy.copy(get_link(self, None))])

        self.logger.info("Number of links {}".format(len(all_link_stats)))

        all_link_repr = ''
        dhcp_links = copy.copy(get_link(self, self.dhcp_switch))
        self.dhcp_link_stats = [(l.src.dpid, l.dst.dpid, l.src.port_no, l.dst.port_no) for l in dhcp_links]
        print("dhcp links:  {}".format(self.dhcp_link_stats))
        for s1, s2, p1, p2 in all_link_stats:
            # 如果之前没有记录才新增邻居记录，并初始化
            if not (self.topo.find_adjacent(s1, s2)) and not (self.topo.find_adjacent(s2, s1)):
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
                if (s.dp.id, port.port_no) not in intra_port:
                    self.edge_switch.append((s, port.port_no))
                    self.logger.info("edge_switch:{}   port:{}".format(s.dp.id, port.port_no))

    def dhcp_relay_handler(self, msg):

        in_port = msg.match['in_port']
        dpid = msg.datapath.id

        for s, p, g in self.dhcp_relay:
            if dpid == s:
                gateway = g
                link_port = p
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
            "Received a DHCP packet in dhcp-relay switch:{}  port:{}  type:{}  "
            "\n".format(
                dpid, in_port, dhcp_type))
        if (dhcp_type == dhcp.DHCP_DISCOVER or dhcp_type == dhcp.DHCP_REQUEST) and in_port == link_port:
            if len(self.dhcp_link_stats) > 0:
                index = random.randint(0, len(self.dhcp_link_stats) - 1)
                send_switch = self.dhcp_link_stats[index][1]
                # send_switch = 5
                send_port = self.dhcp_link_stats[index][3]
                # send_port = 6
                actions = [get_switch(self, send_switch)[0].dp.ofproto_parser.OFPActionOutput(send_port)]
                eth.dst = self.switch_adds[(self.dhcp_switch, self.dhcp_link_stats[index][2])]
                eth.dst = self.switch_adds[(self.dhcp_switch, 2)]
                if pkt_ipv4.src == "0.0.0.0" and pkt_ipv4.dst == "255.255.255.255":
                    pkt_dhcp.hops += 1
                    pkt_dhcp.giaddr = gateway
                    pkt_ipv4.src = gateway
                    pkt_ipv4.dst = self.dhcp_ip[int(self.dhcp_link_stats[index][2]) - 1]
                    # pkt_ipv4.dst = '192.168.0.2'
                pkt_udp.csum = 0
                pkt.serialize()
                msg.data = pkt.data + self.addPadding(len(msg.data) - len(pkt.data))

                if pkt_dhcp.hops <= 16:

                    self.send_out(get_switch(self, send_switch)[0], actions, msg.data)
                    self.logger.info(
                        "Send out a DHCP packet in dhcp-relay switch:{}  port:{}  type:{}  "
                        "\n".format(
                            send_switch, send_port, dhcp_type))
            # 差点逻辑 后面补
        elif dhcp_type == dhcp.DHCP_OFFER or dhcp_type == dhcp.DHCP_ACK:
            for s, p, g in self.dhcp_relay:
                if pkt_dhcp.giaddr == g:
                    send_switch = s
                    actions = [get_switch(self, send_switch)[0].dp.ofproto_parser.OFPActionOutput(p)]
                    # 非广播报文
                    if pkt_dhcp.flags == 0:
                        eth.dst = pkt_dhcp.chaddr
                    else:
                        eth.dst = "ff:ff:ff:ff:ff:ff"
                    if pkt_dhcp.yiaddr != pkt_ipv4.dst:
                        pkt_ipv4.src = pkt_dhcp.giaddr
                        pkt_ipv4.dst = pkt_dhcp.yiaddr
                    pkt_udp.dst_port = 68
                    pkt_udp.csum = 0
                    pkt.serialize()
                    msg.data = pkt.data + self.addPadding(len(msg.data) - len(pkt.data))

                    self.logger.info(
                        "Send out a DHCP packet in dhcp-relay switch:{}  port:{}  type:{}  "
                        "\n".format(
                            send_switch, p, dhcp_type))
                    self.send_out(get_switch(self, send_switch)[0], actions, msg.data)

                    break

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
                if arp_dst_ip == self.nat_ip or self.ipINvpn(arp_dst_ip, in_port, datapath.id):
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

                elif in_port != self.nat_switch_port or datapath.id != self.nat_switch_id:
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
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # 寻路并转发，要修改mac
        dst_mac, dst_switch, final_port = self.arp_table[dst_ip]

        # self.logger.info(
        #     "Origin Packet dst_mac is {}".format(packet.Packet(msg.data).get_protocols(ethernet.ethernet)[0].dst))
        # # 修改报文目的MAC
        # self.logger.info(
        #     "I want to change dst_mac to {}".format(dst_mac))
        pkt = packet.Packet(msg.data)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        origin_mac = eth.dst
        eth.dst = dst_mac
        if origin_mac == eth.dst and (curr_switch,in_port) not in self.edge_switch:
            actions = [parser.OFPActionOutput(OFPP_IN_PORT)]
        else:
            pkt.serialize()
            msg.data = pkt.data
            # self.logger.info(
            #     "After changed dst_mac is {}".format(packet.Packet(msg.data).get_protocols(ethernet.ethernet)[0].dst))
            # print(self.arp_table)
            # 找到源和目的主机的mac及连接的虚拟机
            self.logger.info("Received a Packet from intranet {} to intranet {} change MAC from {} to "
                             "{} \n".format(pkt_ipv4.src,pkt_ipv4.dst,origin_mac,dst_mac))

            shortest_path = self.topo.Dijkstra(
                curr_switch,
                dst_switch,
                in_port,
                final_port)
            # self.logger.info(
                # "The shortest path from {} to {} contains {} switches".format(src_ip, dst_ip, len(shortest_path)))
            assert len(shortest_path) > 0

            path_str = ''

            # (s1,inport,outport)->(s2,inport,outport)->...->(dest_switch,inport,outport)
            for s, ip, op in shortest_path:
                path_str = path_str + "--{}-{}-{}--".format(ip, s, op)

            # self.logger.info("The shortset path from {} to {} is {}".format(curr_switch, dst_switch, path_str))
            self.logger.info(
                "Configure the shortset path from {} to {} —— {}\n".format(src_ip, dst_ip, path_str))

            # self.logger.info("Have calculated the shortest path from {} to {}".format(curr_switch, dst_switch))

            # self.logger.info("Now configuring switches of interest")
            self.configure_path(shortest_path, msg, origin_mac, dst_mac, dst_ip)
            # self.logger.info("Configure done")
            # sleep(1)
            out_port = shortest_path[-1][2]
            in_port = shortest_path[-1][1]
            actions = [parser.OFPActionOutput(out_port)]
            out_switch = get_switch(self, shortest_path[-1][0])[0]
            datapath = out_switch.dp
            parser = datapath.ofproto_parser

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        # send the packet out to avoid packet loss
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            actions=actions,
            in_port=in_port,
            data=data
        )
        datapath.send_msg(out)

    def send_packet(self, curr_switch, in_port, src_ip, dst_ip, msg, dst_mac=None, dst_switch=None, final_port=None,
                    src_mac=None, actions=[]):
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
            if src_ip not in self.arp_table:
                pkt = packet.Packet(msg.data)
                eth = pkt.get_protocols(ethernet.ethernet)[0]
                src_mac = eth.src
                self.arp_table[src_ip] = (src_mac, curr_switch, in_port)
            src_mac, _, _ = self.arp_table[src_ip]
        # src_mac, curr_switch, in_port = self.arp_table[src_ip]
        shortest_path = self.topo.Dijkstra(
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
        self.configure_path(shortest_path, msg, src_mac, dst_mac, actions)
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

                    pkt.serialize()

                    actions = [parser.OFPActionOutput(self.nat_switch_port)]
                    self.send_out(self.nat_switch, actions, pkt.data)

                elif in_port == self.nat_switch_port and curr_switch == self.nat_switch_id:
                    pkt = packet.Packet(self.buffer[i][3].data)
                    eth = pkt.get_protocols(ethernet.ethernet)[0]
                    parser = self.nat_switch.dp.ofproto_parser
                    pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
                    print(pkt_ipv4.dst)
                    dst_mac, dst_switch_id, final_port = self.arp_table[pkt_ipv4.dst]
                    # print("find switch {} port {} ".format(dst_switch_id, final_port))
                    eth.dst = dst_mac
                    print(eth.dst)
                    pkt.serialize()
                    actions = [parser.OFPActionOutput(final_port)]
                    dst_switch = copy.copy(get_switch(self, dst_switch_id))[0]
                    out = parser.OFPPacketOut(
                        datapath=dst_switch.dp,
                        buffer_id=dst_switch.dp.ofproto.OFP_NO_BUFFER,
                        in_port=dst_switch.dp.ofproto.OFPP_CONTROLLER,
                        actions=actions, data=pkt.data)
                    dst_switch.dp.send_msg(out)
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
        # 不在私网内
        if not self.ipInSubnet(dst_ip, self.net_ip) and not (
                self.ipInSubnet(pkt_ipv4.dst, "/".join((self.nat_ip, self.nat_mask)))):
            # 修改原ip
            dst_ip = self.net_getaway_ip
        # 存储报文
        self.buffer.append([src_ip, dst_ip, 20, msg])
        self.logger.info("\n----------------Stor a Packet and Send ARP in edge_switch for {}----------------".format(dst_ip))

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
                src=eth_src if s.dp.id!=self.nat_switch_id else self.switch_adds[(self.nat_switch_id, self.nat_switch_port)]))

            # add arp protocol
            arp_send.add_protocol(arp.arp(
                opcode=arp.ARP_REQUEST,
                src_mac=eth_src if s.dp.id!=self.nat_switch_id else self.switch_adds[(self.nat_switch_id, self.nat_switch_port)],
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
            # print(dst_ip)
            s.dp.send_msg(out)
        print("\n")

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
        datapath = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        parser = self.nat_switch.dp.ofproto_parser
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_udp = pkt.get_protocol(udp.udp)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        if pkt_icmp and pkt_icmp.type == icmp.ICMP_ECHO_REQUEST and pkt_ipv4.dst==self.nat_ip:
            icmp_reply = packet.Packet()
            echo = pkt_icmp.data
            echo.data = bytearray(echo.data)
            icmp_reply.add_protocol(ethernet.ethernet(
                ethertype=ether.ETH_TYPE_IP,
                dst=eth.src,
                src=self.switch_adds[(self.nat_switch_id, self.nat_switch_port)]))
            icmp_reply.add_protocol(ipv4.ipv4(version=4, header_length=5, tos=0, total_length=84,
                       identification=0, flags=0, offset=0, ttl=64,
                       proto=inet.IPPROTO_ICMP, csum=0,
                       src=self.nat_ip, dst=pkt_ipv4.src))
            icmp_reply.add_protocol(icmp.icmp(icmp.ICMP_ECHO_REPLY, code=0, csum=0, data=echo))
            icmp_reply.serialize()
            actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(
                datapath=self.nat_switch.dp,
                buffer_id=self.nat_switch.dp.ofproto.OFP_NO_BUFFER,
                in_port=self.nat_switch.dp.ofproto.OFPP_CONTROLLER,
                actions=actions, data=icmp_reply.data)
            self.nat_switch.dp.send_msg(out)
            return
        # icmp
        elif pkt_icmp and pkt_icmp.type == icmp.ICMP_ECHO_REPLY:
            # 找到icmp未有记录
            if pkt_icmp.data.id in self.icmp_in:

                # 来个icmp报文就便利寿命减一
                self.ICMPTTLdes()

                dst_ip = pkt_ipv4.dst
                dst_id = pkt_icmp.data.id
                pkt_ipv4.dst = self.icmp_in[pkt_icmp.data.id][0]
                pkt_icmp.data.id = self.icmp_in[pkt_icmp.data.id][1]
                pkt_icmp.csum = 0
                # print("Change origin dst IP to {}".format(pkt_ipv4.dst))
                pkt.serialize()
                msg.data = pkt.data
                # 找出在一个子网的有主机边缘交换机及mac
                self.logger.info(
                    "Received a ICMP Packet to our network from internet {} to {} id:{} DNAT to {} id:{} \n".format(
                        pkt_ipv4.src,dst_ip,dst_id,pkt_ipv4.dst,pkt_icmp.data.id))
                if self.find(pkt_ipv4.dst):
                    dst_mac, dst_switch_id, final_port = self.arp_table[pkt_ipv4.dst]
                    # print("find switch {} port {} ".format(dst_switch_id, final_port))
                    eth.dst = dst_mac
                    actions = [parser.OFPActionOutput(final_port)]
                    dst_switch = copy.copy(get_switch(self, dst_switch_id))[0]
                    pkt.serialize()

                    out = parser.OFPPacketOut(
                        datapath=dst_switch.dp,
                        buffer_id=dst_switch.dp.ofproto.OFP_NO_BUFFER,
                        in_port=dst_switch.dp.ofproto.OFPP_CONTROLLER,
                        actions=actions, data=pkt.data)
                    dst_switch.dp.send_msg(out)
                else:
                    self.stor(msg)
            return

        # tcp
        elif pkt_tcp:
            # 找到tcpp未有记录
            if pkt_tcp.dst_port in self.tcp_in:
                # self.logger.info(
                #     "----------------Received a packet to our network from internet2 , src_ip: {}   -----------------------------".format(
                #         pkt_ipv4.src))
                dst_ip = pkt_ipv4.dst
                dst_port = pkt_tcp.dst_port
                pkt_ipv4.dst = self.tcp_in[pkt_tcp.dst_port][0]
                pkt_tcp.dst_port = self.tcp_in[pkt_tcp.dst_port][1]
                pkt_tcp.csum = 0
                # print("Change origin dst IP to {}".format(pkt_ipv4.dst))
                pkt.serialize()
                msg.data = pkt.data
                self.logger.info(
                    "Received a TCP Packet to our network from internet {}:{} to {}:{} DNAT to {}:{} \n".format(
                        pkt_ipv4.src,pkt_tcp.src_port,dst_ip,dst_port,pkt_ipv4.dst,pkt_tcp.dst_port))
                # 找出在一个子网的有主机边缘交换机及mac
                if self.find(pkt_ipv4.dst):
                    # print(self.arp_table)
                    dst_mac, dst_switch_id, final_port = self.arp_table[pkt_ipv4.dst]
                    # print("find switch {} port {} ".format(dst_switch_id, final_port))
                    eth.dst = dst_mac
                    # print(eth.dst)
                    actions = [parser.OFPActionOutput(final_port)]
                    pkt.serialize()

                    dst_switch = copy.copy(get_switch(self, dst_switch_id))[0]
                    out = parser.OFPPacketOut(
                        datapath=dst_switch.dp,
                        buffer_id=dst_switch.dp.ofproto.OFP_NO_BUFFER,
                        in_port=dst_switch.dp.ofproto.OFPP_CONTROLLER,
                        actions=actions, data=pkt.data)
                    dst_switch.dp.send_msg(out)
                else:
                    self.stor(msg)
                    return
            else:
                return


        # udp
        elif pkt_udp:
            # 找到udp未有记录
            if pkt_udp.dst_port in self.udp_in:
                dst_ip = pkt_ipv4.dst
                dst_port = pkt_udp.dst_port
                pkt_ipv4.dst = self.udp_in[pkt_udp.dst_port][0]
                pkt_udp.dst_port = self.udp_in[pkt_udp.dst_port][1]
                pkt_udp.csum = 0
                # print("Change origin dst IP to {}".format(pkt_ipv4.dst))
                pkt.serialize()
                msg.data = pkt.data
                # 找出在一个子网的有主机边缘交换机及mac
                self.logger.info(
                    "Received a UDP Packet to our network from internet {}:{} to {}:{}  DNAT to {}:{}\n".format(
                        pkt_ipv4.src,pkt_udp.src_port,dst_ip,dst_port,pkt_ipv4.dst,pkt_udp.dst_port))
                if self.find(pkt_ipv4.dst):
                    dst_mac, dst_switch_id, final_port = self.arp_table[pkt_ipv4.dst]
                    # print("find switch {} port {} ".format(dst_switch_id, final_port))
                    eth.dst = dst_mac
                    actions = [parser.OFPActionOutput(final_port)]
                    dst_switch = copy.copy(get_switch(self, dst_switch_id))[0]
                    pkt.serialize()
                    out = parser.OFPPacketOut(
                        datapath=dst_switch.dp,
                        buffer_id=dst_switch.dp.ofproto.OFP_NO_BUFFER,
                        in_port=dst_switch.dp.ofproto.OFPP_CONTROLLER,
                        actions=actions, data=pkt.data)
                    dst_switch.dp.send_msg(out)
                else:
                    self.stor(msg)
                    return
            else:
                return
        else:
            return
            # 找路
        shortest_path = self.topo.Dijkstra(
            datapath.id, dst_switch.dp.id, in_port, final_port
        )
        # self.logger.info(
        #     "The shortest path from {} to {} contains {} switches".format(pkt_ipv4.src, pkt_ipv4.dst,
        #                                                                   len(shortest_path)))
        assert len(shortest_path) > 0

        path_str = ''

        # (s1,inport,outport)->(s2,inport,outport)->...->(dest_switch,inport,outport)
        for s, ip, op in shortest_path:
            path_str = path_str + "--{}-{}-{}--".format(ip, s, op)

        # self.logger.info(
            # "The shortset path from {} to {} is {}".format(datapath.id, dst_switch.dp.id, path_str))
        self.logger.info("Configure the shortset path from {} to {} —— {}\n".format(pkt_ipv4.src, pkt_ipv4.dst, path_str))

        # self.logger.info(
            # "Have calculated the shortest path from {} to {}".format(datapath.id, dst_switch.dp.id))

        # self.logger.info("Now configuring switches of interest")
        # self.logger.info("NAT IN !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

        self.configure_path(shortest_path, msg, None, eth.dst, self.nat_ip)
        # self.logger.info("Configure done")

    def NAT_out(self, msg):
        datapath = msg.datapath
        in_port = msg.match['in_port']
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
            if self.net_getaway_ip in self.arp_table and not (
                    self.ipInSubnet(pkt_ipv4.dst, "/".join((self.nat_ip, self.nat_mask)))):
                eth.dst = self.arp_table[self.net_getaway_ip][0]
            elif pkt_ipv4.dst in self.arp_table:
                eth.dst = self.arp_table[pkt_ipv4.dst][0]
            else:
                self.stor(msg)
                return
            src_id = pkt_icmp.data.id
            # 修改id
            pkt_icmp.data.id = self.icmp_out[(src_ip, pkt_icmp.data.id)]
            self.ICMPTTLinit(pkt_icmp.data.id)
            # 修改原ip
            pkt_ipv4.src = self.nat_ip
            self.logger.info(
                "send a ICMP Packet to internet changed_ip is from {} id:{} to {} SNAT to {} id:{}\n".format(src_ip,src_id, pkt_ipv4.src,self.nat_ip,pkt_icmp.data.id))
            pkt_icmp.csum = 0
            pkt.serialize()
            self.send_out(self.nat_switch, actions, pkt.data)
            return

        elif pkt_tcp:
            # 找到icmp未有记录
            src_port = copy.copy(pkt_tcp.src_port)
            if (pkt_ipv4.src, pkt_tcp.src_port) not in self.tcp_out:
                # 使得变换后icmp不冲突
                while src_port in self.tcp_in:
                    src_port += 1

                self.tcp_out[(pkt_ipv4.src, pkt_tcp.src_port)] = src_port
                self.tcp_in[src_port] = (pkt_ipv4.src, pkt_tcp.src_port)

            # sleep(1)
            src_ip = copy.copy(pkt_ipv4.src)
            actions = [parser.OFPActionOutput(self.nat_switch_port)]
            origin_mac = eth.dst
            # 修改mac
            if self.net_getaway_ip in self.arp_table and not (
                    self.ipInSubnet(pkt_ipv4.dst, "/".join((self.nat_ip, self.nat_mask)))):
                eth.dst = self.arp_table[self.net_getaway_ip][0]
            elif pkt_ipv4.dst in self.arp_table:
                eth.dst = self.arp_table[pkt_ipv4.dst][0]
            else:
                self.stor(msg)
                return

            # 修改port
            pkt_tcp.src_port = self.tcp_out[(src_ip, pkt_tcp.src_port)]
            # 修改原ip
            pkt_ipv4.src = self.nat_ip
            self.logger.info(
                "send a TCP Packet to internet changed_ip is from {}:{} to {}:{} SNAT to {}:{}\n".format(src_ip, src_port, pkt_ipv4.dst,
                                                                            pkt_tcp.dst_port, pkt_ipv4.src,pkt_tcp.src_port))
            pkt_tcp.csum = 0
            pkt.serialize()
            self.send_out(self.nat_switch, actions, pkt.data)

        elif pkt_udp:
            # 找到icmp未有记录
            src_port = copy.copy(pkt_udp.src_port)

            if (pkt_ipv4.src, pkt_udp.src_port) not in self.udp_out:
                # 使得变换后icmp不冲突
                while src_port in self.udp_in:
                    src_port += 1

                self.udp_out[(pkt_ipv4.src, pkt_udp.src_port)] = src_port
                self.udp_in[src_port] = (pkt_ipv4.src, pkt_udp.src_port)

            src_ip = copy.copy(pkt_ipv4.src)
            actions = [parser.OFPActionOutput(self.nat_switch_port)]
            origin_mac = eth.dst

            # 修改mac
            if self.net_getaway_ip in self.arp_table and not (
                    self.ipInSubnet(pkt_ipv4.dst, "/".join((self.nat_ip, self.nat_mask)))):
                eth.dst = self.arp_table[self.net_getaway_ip][0]
            elif pkt_ipv4.dst in self.arp_table:
                eth.dst = self.arp_table[pkt_ipv4.dst][0]
            else:
                self.stor(msg)
                return
            # 修改id
            pkt_udp.src_port = self.udp_out[(src_ip, pkt_udp.src_port)]
            # 修改原ip
            pkt_ipv4.src = self.nat_ip
            self.logger.info(
                "send to internet changed_ip is from {}:{} to {}:{} SNAT to {}:{}\n".format(src_ip, src_port, pkt_ipv4.dst,
                                                                            pkt_udp.dst_port,self.nat_ip,pkt_udp.src_port))
            pkt_udp.csum = 0
            pkt.serialize()
            self.send_out(self.nat_switch, actions, pkt.data)
        else:
            return
        # 找路
        shortest_path = self.topo.Dijkstra(
            datapath.id, self.nat_switch_id, in_port, self.nat_switch_port
        )                                                               len(shortest_path)))
        assert len(shortest_path) > 0
        path_str = ''
        for s, ip, op in shortest_path:
            path_str = path_str + "--{}-{}-{}--".format(ip, s, op)
        self.logger.info("Configure the shortset path from {} to {} —— {}\n".format(src_ip, pkt_ipv4.dst, path_str))
        self.configure_path(shortest_path, msg, origin_mac, eth.dst, pkt_ipv4.dst)


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

    # 判断在不在vpn网络里
    def ipINvpn(self, ip, in_port =None , dpid =None):
        if in_port and dpid and (in_port != self.nat_switch_port or dpid != self.nat_switch_id):
            return False
        for net in self.vpn_net:

            if self.ipInSubnet(ip, net):
                return True
        return False

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

