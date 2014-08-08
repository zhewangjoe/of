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
	arppkt = None

	# If this an ARP Packet srcd at the server, 
        # Then we drop it not to confuse the MAC learning
        # At the hosts
        if packetArpSrcIp(msg, self._serverip):
           #print("DROP ARP Packet From Server!")
           return

	# If this is an ARP Request for the server iP
        # create new ARP request and save it in arppkt
        if packetIsRequestARP(msg) : 
           #print("Packet is an ARP Request")
           if packetArpDstIp(msg, self._serverip):
		arppkt = createArpRequest(msg, self._proxyip)
        # If this is an ARP Reply from the proxy
        # create new ARP reply  and save it in arppkt
        if packetIsReplyARP(msg) : 
           #print("Packet is an ARP Reply")
           if packetArpSrcIp(msg, self._proxyip):
		arppkt = createArpReply(msg, self._serverip)
        # If we haven't created a new arp packet, send the one we 
        # received
        if arppkt is None :
		SimpleSwitch._packet_in_handler(self, ev)
        	return
	actions = [datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)]

	out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, in_port=msg.in_port, buffer_id=0xffffffff,
            data=arppkt.data, actions=actions)
        datapath.send_msg(out)

    def _handle_PacketInTCP(self, ev):

	msg = ev.msg
        datapath = msg.datapath
	out_port = self.get_out_port(msg)
	parser = datapath.ofproto_parser
	ofproto = datapath.ofproto
	pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        dst = eth.dst
	src = eth.src
	ethertype = eth.ethertype
	t = pkt.get_protocol(tcp.tcp)
	srcport = t.src_port
	dstport = t.dst_port	

	actions = []
	match = parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst), dl_type=ethertype)
	if packetDstIp(msg, self._serverip) : 
        	if packetDstTCPPort(msg, self._serverport) :
			match = parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst), tp_dst=self._serverport, dl_type=ethertype)
			actions.append( parser.OFPActionSetTpDst( self._proxyport ) )
			actions.append( parser.OFPActionSetNwDst( ipv4_to_int( self._proxyip ) ) )

	if packetSrcIp(msg, self._proxyip) :
		if packetSrcTCPPort(msg, self._proxyport) :
			match = parser.OFPMatch(in_port=msg.in_port, dl_src=haddr_to_bin(src), tp_src=self._proxyport, dl_type=ethertype)
			actions.append( parser.OFPActionSetTpSrc( self._serverport ) )
			actions.append( parser.OFPActionSetNwSrc( ipv4_to_int( self._serverip ) ) )
	
	actions.append(parser.OFPActionOutput(out_port))
	
	if out_port != ofproto.OFPP_FLOOD:
		mod = parser.OFPFlowMod(
            	    datapath=datapath, match=match, cookie=0,
                    command=ofproto.OFPFC_ADD, idle_timeout=10, hard_timeout=30,
            	    priority=ofproto.OFP_DEFAULT_PRIORITY,
            	    flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        	datapath.send_msg(mod)
		
	out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions)
        datapath.send_msg(out)
