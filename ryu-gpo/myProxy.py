from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import ethernet
from simple_switch import SimpleSwitch
from utils import *

SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))
config_file = os.path.join(SCRIPT_PATH, "proxy.config")

class ProxySwitch(SimpleSwitch):


    def __init__(self, *args, **kwargs):
        SimpleSwitch.__init__(self, *args, **kwargs)
        config = readConfigFile(config_file)
	self._serverip = config["general"]['server_ip']
	self._serverport = int(config["general"]['server_port'])
        self._proxyip = config["general"]['proxy_ip']
        self._proxyport = int(config["general"]['proxy_port'])

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
	msg = ev.msg
        datapath = msg.datapath

        self.macLearningHandle(msg)

	if packetIsARP(msg) :
                self._handle_PacketInARP(ev)
                return

	if packetIsTCP(msg) :
        	self._handle_PacketInTCP(ev)
        	return
        SimpleSwitch._packet_in_handler(self, ev)

    def _handle_PacketInARP(self, ev):
	msg = ev.msg
        datapath = msg.datapath	
	parser = datapath.ofproto_parser
        arppkt = None

	# If this an ARP Packet srcd at the server, 
        # Then we drop it not to confuse the MAC learning
        # At the hosts
        if packetArpSrcIp(msg, self._serverip):
           return

	# XXX If this is an ARP Request for the server iP
        # create new ARP request and save it in arppkt
        
        # XXX If this is an ARP Reply from the proxy
        # create new ARP reply  and save it in arppkt

        # If we haven't created a new arp packet, send the one we 
        # received
        if arppkt is None :
		SimpleSwitch._packet_in_handler(self, ev)
        	return

        # Send a packet out with the ARP
	actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)]

        sendPacketOut(msg=msg, actions=actions, data=arppkt.data)

    def _handle_PacketInTCP(self, ev):

	msg = ev.msg
        datapath = msg.datapath
	out_port = self.get_out_port(msg)
	parser = datapath.ofproto_parser
	ofproto = datapath.ofproto

	actions = []
        # XXX If packet is destined to serverip:server port
        # make the appropriate rewrite

        # XXX If packet is sourced at proxyip:proxy port
        # make the appropriate rewrite
	
	actions.append(parser.OFPActionOutput(out_port))
        
        self.forward_packet(msg, actions, out_port)
