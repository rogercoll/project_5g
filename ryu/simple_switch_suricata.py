# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_2
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4
from ryu.lib.packet import ether_types
from ryu.lib import hub
import socket
import os
import _thread
import json
from netaddr import *

ips = {'10.0.0.1': '00:00:00:00:00:01', '10.0.0.2': '00:00:00:00:00:02', '10.0.0.3': '00:00:00:00:00:03', '10.0.0.4': '00:00:00:00:00:04', '10.0.0.5': '00:00:00:00:00:05'}

class SimpleSwitch12(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]
    alerts = []
    suricata_port = 5

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch12, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.mac_to_port = {}
        self.flows = [] 
        self.monitor_thread = hub.spawn(self.listen_suricata_alerts)
        #_thread.start_new_thread( self.listen_suricata_alerts )
    
    def listen_suricata_alerts(self):
        print("Connecting...")
        if os.path.exists("/tmp/ryusock"):
            os.remove("/tmp/ryusock")
        
        print("Opening socket...")
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind("/tmp/ryusock")

        print("Listening...")
        server.listen(1)
        conn, addr = server.accept()
        while True:
            datagram = conn.recv(1024)
            if not datagram:
                break
            else:
                try:
                    y = json.loads(datagram)
                    self.alerts.append(y)
                    print(y)
                    print(y['alert']['signature'])
                    print(len(self.flows))
                    if 'alert' in y:
                        if y['alert']['signature'] == 'LOCAL_TCP_DOS':
                            print("DOS attack detected, mitigating it...")
                            for dp in self.datapaths.values():
                                print(len(self.datapaths))
                                print(y['dest_ip'])
                                dst_ip = EUI(ips[y['dest_ip']]) 
                                src_ip = EUI(ips[y['src_ip']])
                                print("Going to Add flow to drop incomping packets from ", y['src_ip'])
                                self.add_flow(dp, 1, dst_ip,src_ip,[], 10)
                except Exception as e:
                    print(e)

    def add_flow(self, datapath, port, dst, src, actions, level):
        print("Adding flow...")
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(in_port=port,
                                                 eth_dst=dst,
                                                 eth_src=src)
        if actions == None:
            inst = [datapath.ofproto_parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS), []]
        else:
            inst = [datapath.ofproto_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, cookie=0, cookie_mask=0, table_id=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=level, buffer_id=ofproto.OFP_NO_BUFFER,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            flags=0, match=match, instructions=inst)
        datapath.send_msg(mod)
        print("Flow added")
        return mod

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port),datapath.ofproto_parser.OFPActionOutput(self.suricata_port)]
        #actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.flows.append(self.add_flow(datapath, in_port, dst, src, actions, 0))

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)
