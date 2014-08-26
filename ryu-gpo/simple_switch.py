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

"""
An OpenFlow 1.0 L2 learning switch implementation.
"""

import logging
import struct

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from utils import *
'''
This file is edited from Ryu example which is located at  ryu/ryu/app/simple_switch.py.
According to its licecse(please don't trust my reading and read it), we can modify and use it as long as we keep the old license and state we've change the code. --Joe
'''
class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    def add_flow(self, actions, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = getFullMatch( msg )

        mod = parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=10, hard_timeout=30,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    def get_out_port(self,msg):

	pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
	datapath = msg.datapath
	dpid = datapath.id
	ofproto = datapath.ofproto

	if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
	return out_port

    def macLearningHandle(self, msg) :
	# learn a mac address to avoid FLOOD next time.
	datapath = msg.datapath
	pkt = packet.Packet(msg.data)
	eth = pkt.get_protocol(ethernet.ethernet)
	src = eth.src
	dpid = datapath.id	

	self.mac_to_port.setdefault(dpid, {})
	
	self.mac_to_port[dpid][src] = msg.in_port

    def forward_packet(self, msg, actions, out_port) :

	datapath = msg.datapath
	ofproto = datapath.ofproto

	# install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow( actions, msg)

        sendPacketOut(msg=msg, actions=actions, buffer_id=msg.buffer_id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
	eth = pkt.get_protocol(ethernet.ethernet)
	dst = eth.dst
        src = eth.src

        dpid = datapath.id

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

	self.macLearningHandle(msg)

	out_port = self.get_out_port(msg)	

        actions = [parser.OFPActionOutput(out_port)]

	self.forward_packet(msg, actions, out_port)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)
