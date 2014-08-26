from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from simple_switch import SimpleSwitch
from utils import *

SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))
config_file = os.path.join(SCRIPT_PATH, "duplicate.config")

'''
The main difference between this and Pox version is that
it uses confing file, as Ryu does not providing a way to pass argument into controller.
In the config file, I'm using port number directly, instead of iface name, because you cannot write a similar function like getOpenFlowPort().
Explicitly get switch feature cannot get those info of course.
However, I don't think that's needed.
Because when we use 'sudo ovs-ofctl show br0', it will show port<-->iface<-->mac. So we don't really need iface name to know port.
'''
class DuplicateTrafficSwitch(SimpleSwitch):


    def __init__(self, *args, **kwargs):
        SimpleSwitch.__init__(self, *args, **kwargs)
        config = readConfigFile(config_file)
	self._of_duplicate_port=int(config["general"]["duplicate_port"])

    '''
    I didn't log because
    to log, we need parse the packet one more time, by:
    pkt = packet.Packet(msg.data)
    eth = pkt.get_protocol(ethernet.ethernet)
    dstmac = eth.dst
    srcmac = eth.src
    ip = pkt.get_protocol(ipv4.ipv4)
    srcip = ip.src
    dstip = ip.dst
    t = pkt.get_protocol(tcp.tcp)
    srcport = t.src_port
    dstport = t.dst_port
    slef.logger.info( "packet in %s %i s% --> %s %i %s", srcip, srcport, srcmac, dstip, dstport, dstmac )

    So add log when you need and parse accordingly.
    '''
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
	msg = ev.msg
        datapath = msg.datapath
	parser = datapath.ofproto_parser	

        self.macLearningHandle(msg)

        out_port = self.get_out_port(msg)

        actions = [parser.OFPActionOutput(out_port), parser.OFPActionOutput(self._of_duplicate_port)]

        self.forward_packet(msg, actions, out_port)
