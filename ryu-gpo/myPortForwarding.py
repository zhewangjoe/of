from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import ethernet
from simple_switch import SimpleSwitch
from utils import *

SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))
config_file = os.path.join(SCRIPT_PATH, "port_forward.config")

class PortForwardingSwitch(SimpleSwitch):


    def __init__(self, *args, **kwargs):
        SimpleSwitch.__init__(self, *args, **kwargs)
        config = readConfigFile(config_file)
        self._serverip = config["general"]['server_ip']
        self._origport = int(config["general"]['orig_port'])
        self._forwport = int(config["general"]['forw_port'])

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath

        self.macLearningHandle(msg)

	if packetIsTCP(msg) :
        self._handle_PacketInTCP(ev)
        return
    SimpleSwitch._packet_in_handler(self, ev)

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
        
        actions = []
        match = parser.OFPMatch(in_port=msg.in_port, dl_dst=haddr_to_bin(dst), dl_type=ethertype)
        
        # XXX If packet is destined to serverip:original port
        # make the appropriate rewrite
        
        # XXX If packet is sourced at serverip:forward port
        # make the appropriate rewrite
        
        '''
        Fun finding: Order in the actions list matters!
        OFPActionOutput needs to be later than OFPActionSetTpDst/Src in the actions list.
        Otherwise, it will send out the packet before changing it.
        '''
        actions.append(parser.OFPActionOutput(out_port))

        # XXX Create the flow mod message	
        
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions)
        datapath.send_msg(out)