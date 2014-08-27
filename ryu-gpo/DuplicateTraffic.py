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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        msg = ev.msg
        
        self.macLearningHandle(msg)

        out_port = self.get_out_port(msg)

        self.forward_packet(msg, [out_port, self._of_duplicate_port])
