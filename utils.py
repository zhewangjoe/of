import ConfigParser
import os
import sys
from ryu.ofproto import ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import arp
from ryu.lib import mac

def readConfigFile(filename) :
    config = None
    filename = os.path.expanduser(filename)
    if not os.path.exists(filename):
    	sys.exit(-1)

    confparser = ConfigParser.RawConfigParser()
    try:
    	confparser.read(filename)
    except ConfigParser.Error as exc:
        print("Config file %s could not be parsed: %s" % (filename, str(exc)))
  # Create a dictionary from the configuration
  # - each section is a key in the dictionary that it's value
  # is a dictionary with (key, value) pairs of configuration
  # parameters
    config = {}
    for sec in confparser.sections():
    	config[sec] = {}
        for (key,val) in confparser.items(sec):
        	config[sec][key] = val

    return config

def packetIsIP(message) :
    pkt = packet.Packet(message.data)

    ip = pkt.get_protocol(ipv4.ipv4)
    if ip is not None :
        return True
    return False

def packetIsARP(message) :
    pkt = packet.Packet(message.data)

    a = pkt.get_protocol(arp.arp)
    if a is not None :
        return True
    return False

def packetIsRequestARP(message) :
    pkt = packet.Packet(message.data)

    a = pkt.get_protocol(arp.arp)
    if a.opcode == arp.ARP_REQUEST :
        return True
    return False

def packetIsReplyARP(message) :
    pkt = packet.Packet(message.data)

    a = pkt.get_protocol(arp.arp)
    if a.opcode == arp.ARP_REPLY :
	return True
    return False

def packetIsTCP(message) :
    pkt = packet.Packet(message.data)

    ip = pkt.get_protocol(ipv4.ipv4)
    if ip is not None and ip.proto == 6 :
	return True
    return False

def packetDstIp(message, ipaddr) :
    if packetIsIP(message):
	pkt = packet.Packet(message.data)
	ip = pkt.get_protocol(ipv4.ipv4)
    	if not cmp(ip.dst, ipaddr):
		return True
    return False

def packetSrcIp(message, ipaddr) :
    if packetIsIP(message):
        pkt = packet.Packet(message.data)
        ip = pkt.get_protocol(ipv4.ipv4)
        if not cmp(ip.src, ipaddr):
                return True
    return False

def packetDstTCPPort(message, tcpport) :
    if packetIsTCP(message) :
	pkt = packet.Packet(message.data)
        dsttcp = pkt.get_protocol(tcp.tcp)
	if dsttcp.dst_port == tcpport :
		return True
    return False

def packetSrcTCPPort(message, tcpport) :
    if packetIsTCP(message) :
        pkt = packet.Packet(message.data)
        srctcp = pkt.get_protocol(tcp.tcp)
	if srctcp.src_port == tcpport :
                return True
    return False

def packetArpDstIp(message, ipaddr) :
    if packetIsARP(message):
        pkt = packet.Packet(message.data)
        a = pkt.get_protocol(arp.arp)
        if not cmp(a.dst_ip, ipaddr):
                return True
    return False

def packetArpSrcIp(message, ipaddr) :
    if packetIsARP(message):
        pkt = packet.Packet(message.data)
        a = pkt.get_protocol(arp.arp)
        if not cmp(a.src_ip, ipaddr):
                return True
    return False

def createArpRequest(message, ip):
    if not packetIsARP(message):
    	print("Packet is not ARP")
    	return
    pkt = packet.Packet(message.data)
    origarp = pkt.get_protocol(arp.arp)
    a = arp.arp(
    	hwtype=origarp.hwtype,
    	proto=origarp.proto,
	src_mac=origarp.src_mac,
    	dst_mac=origarp.dst_mac,
	hlen=origarp.hlen,
    	opcode=arp.ARP_REQUEST,
    	plen=origarp.plen,
	src_ip=origarp.src_ip,
	dst_ip=ip
	)
    e = ethernet.ethernet(
	dst=mac.BROADCAST_STR,
	src=origarp.src_mac,
	ethertype=ether.ETH_TYPE_ARP)    
    p = packet.Packet()
    p.add_protocol(e)
    p.add_protocol(a)
    p.serialize()
    return p

def createArpReply(message, ip):
    if not packetIsARP(message):
        print("Packet is not ARP")
        return
    pkt = packet.Packet(message.data)
    origarp = pkt.get_protocol(arp.arp)
    a = arp.arp(
        hwtype=origarp.hwtype,
        proto=origarp.proto,
        src_mac=origarp.src_mac,
        dst_mac=origarp.dst_mac,
        hlen=origarp.hlen,
        opcode=arp.ARP_REPLY,
        plen=origarp.plen,
        src_ip=ip,
        dst_ip=origarp.dst_ip
        )
    e = ethernet.ethernet(
        dst=origarp.dst_mac,
        src=origarp.src_mac,
        ethertype=ether.ETH_TYPE_ARP)
    p = packet.Packet()
    p.add_protocol(e)
    p.add_protocol(a)
    p.serialize()
    return p

def ipv4_to_int(string):
	ip = string.split('.')
       	assert len(ip) == 4
       	i = 0
       	for b in ip:
    		b = int(b)
        	i = (i << 8) | b
        return i

