from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from simple_switch import SimpleSwitch
from utils import *

SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))
config_file = os.path.join(SCRIPT_PATH, "duplicate.config")

class DuplicateTrafficSwitch(SimpleSwitch):


    def __init__(self, *args, **kwargs):
        SimpleSwitch.__init__(self, *args, **kwargs)
        config = readConfigFile(config_file)
	self._of_duplicate_port=int(config["general"]["duplicate_port"])

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
	msg = ev.msg
        datapath = msg.datapath
	parser = datapath.ofproto_parser	

        self.macLearningHandle(msg)

        out_port = self.get_out_port(msg)

        # XXX Modify the following line to forward packets
        # out the normal port and the duplication port
        actions = [parser.OFPActionOutput(out_port)]

        self.forward_packet(msg, actions, out_port)
