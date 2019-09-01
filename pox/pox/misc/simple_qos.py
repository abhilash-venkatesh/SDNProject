from pox.core import core 
import pox.openflow.libopenflow_01 as of 
from pox.lib.util import dpidToStr 
log = core.getLogger()

s1_dpid=0 
s2_dpid=0

def _handle_ConnectionUp (event):
	global s1_dpid, s2_dpid
	print "ConnectionUp: ", dpidToStr(event.connection.dpid)
	#remember the connection dpidfor switch 
	for m in event.connection.features.ports:
		if m.name == "s1-eth1":
			s1_dpid = event.connection.dpid
			print "s1_dpid=", s1_dpid 
		elif m.name == "s2-eth1": 
			s2_dpid = event.connection.dpid 
			print "s2_dpid=", s2_dpid

def _handle_PacketIn (event): 
	global s1_dpid, s2_dpid 
	print "PacketIn: ", dpidToStr(event.connection.dpid)

	if event.connection.dpid==s1_dpid:
		print "S1 IN"
		msg= of.ofp_flow_mod() 
		msg.priority=1 
		msg.idle_timeout = 0 
		msg.hard_timeout = 0 
		msg.match.dl_type = 0x0806 
		msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL)) 
		event.connection.send(msg)
		
		msg= of.ofp_flow_mod() 
		msg.priority=100 
		msg.idle_timeout = 0 
		msg.hard_timeout = 0 
		msg.match.dl_type = 0x0800
		msg.match.nw_src = "10.0.1.100" 
		msg.match.nw_dst = "10.0.4.100" 
		msg.actions.append(of.ofp_action_enqueue(port = 4, queue_id=1))  
		event.connection.send(msg)
		
		msg= of.ofp_flow_mod() 
		msg.priority=100 
		msg.idle_timeout = 0 
		msg.hard_timeout = 0 
		msg.match.dl_type = 0x0800
		msg.match.nw_src = "10.0.2.100" 
		msg.match.nw_dst = "10.0.4.100" 
		msg.actions.append(of.ofp_action_enqueue(port = 4, queue_id=2))  
		event.connection.send(msg)
		
		msg= of.ofp_flow_mod() 
		msg.priority=10 
		msg.idle_timeout = 0 
		msg.hard_timeout = 0 
		msg.match.dl_type = 0x0800
		msg.match.nw_dst = "10.0.1.100"
		msg.actions.append(of.ofp_action_output(port = 1)) 
		event.connection.send(msg)
		
		msg= of.ofp_flow_mod() 
		msg.priority=10 
		msg.idle_timeout = 0 
		msg.hard_timeout = 0 
		msg.match.dl_type = 0x0800
		msg.match.nw_dst = "10.0.2.100"
		msg.actions.append(of.ofp_action_output(port = 2)) 
		event.connection.send(msg)

		msg= of.ofp_flow_mod() 
		msg.priority=10 
		msg.idle_timeout = 0 
		msg.hard_timeout = 0 
		msg.match.dl_type = 0x0800
		msg.match.nw_dst = "10.0.3.100"
		msg.actions.append(of.ofp_action_output(port = 3)) 
		event.connection.send(msg)
		
		msg= of.ofp_flow_mod() 
		msg.priority=10 
		msg.idle_timeout = 0 
		msg.hard_timeout = 0 
		msg.match.dl_type = 0x0800
		msg.match.nw_dst = "10.0.4.100"
		msg.actions.append(of.ofp_action_output(port = 4)) 
		event.connection.send(msg)
	if event.connection.dpid==s2_dpid:
		msg= of.ofp_flow_mod() 
		msg.priority=1 
		msg.idle_timeout = 0 
		msg.hard_timeout = 0 
		msg.match.in_port = 1
		msg.actions.append(of.ofp_action_output(port = 2)) 
		event.connection.send(msg)
		
		msg= of.ofp_flow_mod() 
		msg.priority=1 
		msg.idle_timeout = 0 
		msg.hard_timeout = 0 
		msg.match.in_port = 2
		msg.actions.append(of.ofp_action_output(port = 1)) 
		event.connection.send(msg)
def launch (): 
	core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
	core.openflow.addListenerByName("PacketIn", _handle_PacketIn) 
