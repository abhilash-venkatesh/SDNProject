from pox.core import *
from netaddr import *
from pox.lib.revent import *
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.packet.icmp import icmp, echo
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpid_to_str
from pox.lib.recoco import Timer

import pox.lib.packet as pkt
import pox.openflow.libopenflow_01 as of
import time
import pox

import ast

from abhilashmodule import *

log = pox.core.getLogger()

s1_dpid=0 
s2_dpid=0
s3_dpid=0

bandwidth=1000 #Mbits/sec

class Switch(object):
  def __init__ (self, connection, s_dpid):
    self.connection = connection
    connection.addListeners(self)

    self.s_dpid = s_dpid

    self.mac_to_port = {}

  def push_flow_label (self, dest_mac, out_port):
    log.debug("!LOG! "+str(self.s_dpid)+"PUSHING FLOW LABEL (for dest mac "+str(dest_mac)+")!")
    msg = of.ofp_flow_mod()
    msg.priority = 150
    msg.match.dl_dst = dest_mac
    msg.actions.append(of.ofp_action_output(port = out_port))
    self.connection.send(msg)
    log.debug("!LOG! "+str(self.s_dpid)+"PUSHED FLOW LABEL (!!! FIXING OUTPUT PORT "+str(out_port)+" with MAC-ID "+str(dest_mac)+" !!!)!")

  def resend_packet (self, packet_in, out_port):
    msg = of.ofp_packet_out()
    msg.data = packet_in

    action = of.ofp_action_output(port = out_port)

    msg.actions.append(action)

    self.connection.send(msg)

  def act_like_hub (self, packet, packet_in):
    self.resend_packet(packet_in, of.OFPP_ALL)

  def act_like_switch (self, packet, packet_in):

    if packet.src not in self.mac_to_port:
	if str(packet.src) != "ff:ff:ff:ff:ff:ff":
		log.debug("!LOG! "+str(self.s_dpid)+": Learning that " + str(packet.src) + " is attached at port " + str(packet_in.in_port))
		self.mac_to_port[packet.src] = packet_in.in_port

    if packet.dst in self.mac_to_port:
      log.debug("!LOG! "+str(self.s_dpid)+" : " + str(packet.dst) + " destination known. only send message to it")
      print "!LOG! "+str(self.s_dpid)+"packet dst "+str(packet.dst)+" port "+str(self.mac_to_port[packet.dst])
      #if str(self.s_dpid) == "2":
      self.push_flow_label(packet.dst,self.mac_to_port[packet.dst])
      self.resend_packet(packet_in, self.mac_to_port[packet.dst])

    else:
      log.debug("!LOG! "+str(self.s_dpid)+" : " + str(packet.dst) + " not known, resend to everybody")
      self.resend_packet(packet_in, of.OFPP_ALL)


  def _handle_PacketIn (self, event):
    packet = event.parsed
    if not packet.parsed:
      log.warning("!LOG! "+str(self.s_dpid)+" : Ignoring incomplete packet")
      return

    packet_in = event.ofp

    #self.act_like_hub(packet, packet_in)
    self.act_like_switch(packet, packet_in)



class Router(object):
    def __init__(self, connection, s_dpid):
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)

	self.s_dpid = s_dpid

        # Buffer for packets waiting for ARP
        self.buffer = {}

        # Use this table to keep track of which ethernet address is on
        # which switch port (keys are MACs, values are ports).
        self.mac_to_port = {}
	750
	self.bandwidth_to_queue = {1:1, 10:2, 50:3, 100:4, 200:5, 500:6, 750:7}
	# This table is used to keep track of the bandwidhts between hosts.
	# keys are source_ips, value is a dictionary with keys dest_ip and bandwidth_val
	self.allocated_bandwidths = {'s1-eth1':{},'s1-eth2':{}}

	self.port_to_interface = {1:'s1-eth1',2:'s1-eth2'}

        # ARP Table
        self.arp_table = {}
        self.arp_table['10.0.1.1'] = 'AA:BB:CC:DD:EE:01'
        self.arp_table['10.0.2.1'] = 'AA:BB:CC:DD:EE:02'
        #self.arp_table['10.0.3.1'] = 'AA:BB:CC:DD:EE:03'
	#self.arp_table['10.0.4.1'] = 'AA:BB:CC:DD:EE:04'

        # Route default flows for ICMP traffic destined to Router Interfaces
        for dest in self.arp_table.keys():
            msg = of.ofp_flow_mod()
            msg.priority = 100
            msg.match.dl_type = ethernet.IP_TYPE
            msg.match.nw_proto = ipv4.ICMP_PROTOCOL
            msg.match.nw_dst = IPAddr(dest)
            msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
            self.connection.send(msg)
	
	# PREPARTION
	# ----------
	# Prepare router for accepting bandwidth request:
	
	# Write  default flows to push custom-port-number traffic (the traffic which is supposed to carry network requirement detail from 		# the host)to the controller, which will be handled by the controller using just another packetIn function call in the code)
	# the above flow must have highest priority (so that we ask switch to send packets destined to this port ALWAYS to controller).
	# Later, inside the packetIn function, after determining if it's an IP packet, determine if it's got tcp payload, and obtain the bandwidth
	# requirements, time duration and destination node from the app layer data. On the hosts, in order to make send this data, create a simple 	   # python program which sends bandwidth requirement (to a certain destination node) to the the default gateway, which is basically forwarded 
	# by the oVs to the controller.
	# 

	# INTEGRATING BANDWIDTH ALLOCATION
	#--------------------------------
	# RESEARCH IF THERE'S NO OTHER WAY FOR DYN BANDWIDTH ALLOCATION, If None, 

	# MultiQueue load balancing for custom bandwidth allocation:
	# Create 10 queues each with bandwidths spanning a range of numbers of your choice.
	# Obtain the parsed bandwidth request from the app layer data and check possibility of approval of the request/
	# For the above step, research how to check if bandwidth is avaliable.
	# Once a request is approved, intimate the source PC about successful allocation of bandwidth.
	# Now, the controller must send flow rules to the switch the the timing and priority of each tweaked such that
	# the net bandwidth that the data has been tranferred is equal to the requested bandwidth.
	# say, divide the requested time duration by k units, for every time_duration/k seconds, send an updated flow to (to promote/depromote) 
	# from current queue, with the intention to bring the current bandwidth approximately equal to the required bandwidth.
	# let's say the available queues are configured with bandwidth: 5Mbps, 10Mbps, 15Mbps.
	# 10.0.1.100 says -> required : 7.5Mbps for 10 seconds to 10.0.4.100
	# take k = 4
	# Now, 10/4 = 2.5 sec
	# send flows to update output bandwidths in, say, the following possible way.
	#  TIME  flow_label_output_queue_bandwidth
	#  0s			5 Mbps
	#  2.5s			10 Mbps
	#  5s			5 Mbps
	#  7.5s			10 Mbps
	#	Avg B/W : 7.5Mbps
	# Higher the k value, the more frequently the flow changes and more the network traffic, and blah blah.
	# Lower the k value, less network traffic, but bandwidth drops and rises oddly. Approriate k value must be chosen.
	#

	msg = of.ofp_flow_mod()
        msg.priority = 200
        msg.match.dl_type = ethernet.IP_TYPE
        msg.match.nw_proto = 0x11
        msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        self.connection.send(msg)

        self.routing_table = {}
        self.routing_table['10.0.1.0/24'] = {'Port': 1, 'RouterInterface':'10.0.1.1'}
        self.routing_table['10.0.2.0/24'] = {'Port': 2, 'RouterInterface':'10.0.2.1'}
        #self.routing_table['10.0.3.0/24'] = {'Port': 3, 'RouterInterface':'10.0.3.1'}
	#self.routing_table['10.0.4.0/24'] = {'Port': 4, 'RouterInterface':'10.0.4.1'}

    def send_UDP_response(self, responseCode, destIP, data):

	routable, destination_network = self.checkRoutableDestination(destIP)
	if routable:
		print "#Building a UDP packet destined for "+str(destIP)
		sourceMAC = self.arp_table[self.routing_table[destination_network]['RouterInterface']]
		destMAC = self.arp_table[destIP]
		output_port = self.routing_table[destination_network]['Port']
		sourceIP = self.routing_table[destination_network]['RouterInterface']

		print "#Source IP : "+str(sourceIP)+" Source MAC : "+str(sourceMAC)+" destMAC : "+str(destMAC) +" output_port : "+str(output_port)		
		if destIP not in self.arp_table:
			print "\n#Sending ARP Request to destination IP ...#"
			self.ARPResolve(destIP,destination_network,output_port)
			print "Waiting for ARP Reply ..."
			while destIP not in self.buffer.keys():
				pass 
			print "ARP Response was received!"

		#Building and sending a UDP response to the client.
		e = pkt.ethernet(src = EthAddr(sourceMAC), dst = EthAddr(destMAC), type = pkt.ethernet.IP_TYPE)
		i = pkt.ipv4(srcip = IPAddr(sourceIP), dstip = IPAddr(destIP), protocol = pkt.ipv4.UDP_PROTOCOL)
		u = pkt.udp(srcport = 10000, dstport = 10000)#,off = 5,win = 1)
		#t.ACK = True
		u.payload = str({"res":responseCode, "data":data})
		i.payload = u
		e.payload = i
		self.resend_packet(e, output_port)

    def ARPResolve(self, destination_ip, destination_network, output_port):
	arp_request = arp()
        arp_request.opcode = arp.REQUEST
        arp_request.protosrc = IPAddr(self.routing_table[destination_network]['RouterInterface'])
        arp_request.protodst = IPAddr(destination_ip)

        arp_request.hwsrc = EthAddr(self.arp_table[self.routing_table[destination_network]['RouterInterface']])
        arp_request.hwdst = EthAddr('00:00:00:00:00:00')

        ether = ethernet()
        ether.type = ether.ARP_TYPE
        ether.src = EthAddr(self.arp_table[self.routing_table[destination_network]['RouterInterface']])
        ether.dst = EthAddr('FF:FF:FF:FF:FF:FF')
        ether.payload = arp_request
        self.resend_packet(ether, output_port)

    def handleBandwidthRequest(self, request):
	global bandwidth
	print "\nThe request is : "+str(request)
	dic = ast.literal_eval(request)
	print "\nDic output works : Requested bandwidth is "+str(dic['bandwidth'])+"!"
	
	routable, destination_network = self.checkRoutableDestination(dic['ip_dst'])
	output_port = self.routing_table[destination_network]['Port']
	output_interface = self.port_to_interface[output_port]
	if routable:
		print "\nBandwidth request for the dest_ip is ROUTABLE!"
		if dic['ip_src'] in self.allocated_bandwidths[output_interface].keys():
			#for desip, bw in self.allocated_bandwidths[output_interface][dic['ip_src']]:
			bandwidth += reverseDicLookup(self.bandwidth_to_queue,self.allocated_bandwidths[output_interface][dic['ip_src']]['bandwidth'])
			print "\nUPDATING REMAINING BANDWIDTH TO "+str(bandwidth)
		if bandwidth - int(dic['bandwidth']) > 0:
			print "\n#Bandwidth request approved ... #"
			print "The PREVIOUS BANDWIDTH TABLE IS :"+str(self.allocated_bandwidths[output_interface])
			
			if dic['ip_src'] in self.allocated_bandwidths[output_interface].keys():
				del self.allocated_bandwidths[output_interface][dic['ip_src']]
			print "\n#Previous flows cleared ... #"
			## DEST ARP QUERY HERE
			if dic['ip_dst'] not in self.arp_table:
				print "\n#Sending ARP Request to destination IP ...#"
				self.ARPResolve(dic['ip_dst'],destination_network,output_port)
				print "Waiting for ARP Reply ..."
				while dic['ip_src'] not in self.buffer.keys():
					pass 
				print "ARP Response was received!"
			self.delete_flow_label(dic['ip_src'])
			self.push_flow_label_bandwidth(dic['ip_src'],dic['ip_dst'],output_port,dic['timeout'],dic['bandwidth'],destination_network)
			print "The NEW BANDWIDTH TABLES ARE :"+str(self.allocated_bandwidths)
			
			bandwidth = bandwidth - int(dic['bandwidth'])
			print "#\nREMAINING BANDWIDTH :"+str(bandwidth)
			self.send_UDP_response(100, dic['ip_src'], bandwidth)
			print "\n#UDP Response Sent#"
			print "\n#Done#"
		else:
			print "#Insufficient bandwidth on "+ self.port_to_interface[out_port]#"
			self.send_UDP_response(50, dic['ip_src'], bandwidth)
    
    def push_flow_label_bandwidth(self, source_ip, dest_ip, out_port, timeout, bandwidth_this,destination_network):
	output_interface = self.port_to_interface[out_port]

	msg = of.ofp_flow_mod()

	msg.idle_timeout = 0
	msg.hard_timeout = timeout	

	msg.match.dl_type = ethernet.IP_TYPE
        #msg.match.nw_proto = ipv4.ICMP_PROTOCOL
	msg.match.nw_src = IPAddr(source_ip)
	#if dest_ip == "10.0.2.100":
	#	print "The flow that's going to be added must match source ip ("+source_ip+") too along with destination ip "+dest_ip
	#	msg.match.nw_src = IPAddr(source_ip)
	#else:
	#	print "source_ip match constraint not added"
	#I SUSPECT MATCHING THIS ENTIRE NETWORK RANGE AND APPENDING A SINGLE MAC ID FOR THE FLOW IS WRONG. DEBUG FROM HERE
        msg.match.nw_dst = IPAddr(dest_ip)
        # msg.match.nw_dst = IPAddr(srcip)

        msg.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(self.arp_table[self.routing_table[destination_network]['RouterInterface']])))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(self.arp_table[dest_ip])))
	
	msg.actions.append(of.ofp_action_enqueue(port = out_port, queue_id=self.bandwidth_to_queue[bandwidth_this]))
	self.connection.send(msg)

	self.allocated_bandwidths[output_interface][source_ip] = {'dest_ip': dest_ip,'bandwidth': self.bandwidth_to_queue[bandwidth_this]} #queueno denotes bandwidth

    def delete_flow_label(self, source_ip):
	msg = of.ofp_flow_mod(command=of.OFPFC_DELETE_STRICT)
	msg.match.dl_type = ethernet.IP_TYPE
	msg.match.nw_src = IPAddr(source_ip)
	self.connection.send(msg)

    def push_flow_label(self, source_ip, dest_ip, out_port):
	
	print "Flow label for destination network : "+self.buffer[dest_ip]['DestinationNetwork']
	msg = of.ofp_flow_mod()
        
	msg.idle_timeout = 0
	msg.hard_timeout = 0

        msg.match.dl_type = ethernet.IP_TYPE
        #msg.match.nw_proto = ipv4.ICMP_PROTOCOL
	msg.match.nw_src = IPAddr(source_ip)
	#if dest_ip == "10.0.2.100":
	#	print "The flow that's going to be added must match source ip ("+source_ip+") too along with destination ip "+dest_ip
	#	msg.match.nw_src = IPAddr(source_ip)
	#else:
	#	print "source_ip match constraint not added"
	#I SUSPECT MATCHING THIS ENTIRE NETWORK RANGE AND APPENDING A SINGLE MAC ID FOR THE FLOW IS WRONG. DEBUG FROM HERE
        msg.match.nw_dst = IPAddr(dest_ip)
        # msg.match.nw_dst = IPAddr(srcip)

        msg.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(self.arp_table[self.routing_table[self.buffer[dest_ip]['DestinationNetwork']]['RouterInterface']])))
        msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(self.arp_table[dest_ip])))

	print 'the flow will set source MAC as interface oda MAC ID: '
	print str((EthAddr(self.arp_table[self.routing_table[self.buffer[dest_ip]['DestinationNetwork']]['RouterInterface']])))
	print ' and dst MAC as destIP oda MAC ID '+str(EthAddr(self.arp_table[dest_ip]))
	
	#if dest_ip == "10.0.2.100":
	#	msg.priority = 250
	#	if source_ip == "10.0.1.100":
	#		queueno=1
	#	elif source_ip == "10.0.1.101": 
	#		queueno=2
	#	else: 
	#		queueno=0
	#	print "PUSHING QOS FLOW for source_ip "+source_ip+" @queue "+str(queueno)
	#	msg.actions.append(of.ofp_action_enqueue(port = 2, queue_id=queueno)) #BUG WAS HERE, CHANGE OUT_PORT NUMBER HERE IN FUTURE UPDATES!
	#	self.allocated_bandwidths[source_ip] = {'dest_ip': dest_ip,'bandwidth': queueno} #queueno denotes bandwidth
	#	log.debug("allocated bandwidths table : "+str(self.allocated_bandwidths))	
	#else:   
	msg.priority = 150     
	print "PUSHING REGULAR FLOW!"       
	msg.actions.append(of.ofp_action_output(port=out_port))

        self.connection.send(msg)
        log.debug("Flow mod for destination network %s sent!", self.buffer[dest_ip]['DestinationNetwork'])
	

    def resend_packet(self, packet_in, out_port):
        """
        Instructs the switch to resend a packet that it had sent to us.
        "packet_in" is the ofp_packet_in object the switch had sent to the
        controller due to a table-miss.
        """
	print "\n--MY APPLICATION : LOG--\n"
	print "OUTPUT port determined : "+str(out_port)

	if packet_in.type == ethernet.IP_TYPE:
		destination_ip = str(packet_in.payload.dstip)
		source_ip = str(packet_in.payload.srcip)

		if destination_ip == "10.0.2.100":
			print "Detected TARGET data packet."

			msg = of.ofp_packet_out()
        		msg.data = packet_in.pack()
        		# Add an action to send to the specified port
        		action = of.ofp_action_output(port=2)
        		msg.actions.append(action)
			self.connection.send(msg)

			print "TARGET data packet sent."
		else:
			print "Detected IP packet not for Target"
			msg = of.ofp_packet_out()
        		msg.data = packet_in.pack()
        		# Add an action to send to the specified port
        		action = of.ofp_action_output(port=out_port)
        		msg.actions.append(action)
			self.connection.send(msg)

	else:
		print "Detected NON IP packet"
		msg = of.ofp_packet_out()
        	msg.data = packet_in.pack()
        	# Add an action to send to the specified port
        	action = of.ofp_action_output(port=out_port)
        	msg.actions.append(action)
		self.connection.send(msg)
	print "\n--MY APPLICATION : LOG CLOSE--\n"
        # Send message to switch
        

    def ARP_Handler(self, packet, packet_in):
        log.debug("ARP FRAME RECEIVED FROM %s" % packet_in.in_port)
	
        if packet.payload.opcode == arp.REQUEST:
            log.debug("IT'S AN ARP REQUEST asking MAC of "+str(packet.payload.protodst)+"from src_ip :"+str(packet.payload.protosrc))

            arp_payload = packet.payload
            arp_request_ip = str(arp_payload.protodst)
            if arp_request_ip in self.arp_table:
		log.debug("I know the MAC of this ARP REQUEST's IP!")
                arp_reply = arp()
                arp_reply.opcode = arp.REPLY
                arp_reply.hwsrc = EthAddr(self.arp_table[arp_request_ip])
                arp_reply.hwdst = arp_payload.hwsrc
                arp_reply.protosrc = arp_payload.protodst
                arp_reply.protodst = arp_payload.protosrc

                ether = ethernet()
                ether.type = ether.ARP_TYPE
                ether.src = EthAddr(self.arp_table[arp_request_ip])
                ether.dst = arp_payload.hwsrc
                ether.payload = arp_reply

                self.resend_packet(ether, packet_in.in_port)
                log.debug("ARP REPLY SENT!")

        elif packet.payload.opcode == arp.REPLY:
            log.debug("IT'S AN ARP REPLY!")

            arp_payload = packet.payload
            hwsrc = str(arp_payload.hwsrc)
            srcip = str(arp_payload.protosrc)
            if srcip not in self.arp_table:
                self.arp_table[srcip] = hwsrc
                self.mac_to_port[hwsrc] = packet_in.in_port
                log.debug("%s %s INSTALLED TO CAM TABLE" % (srcip, hwsrc))

            # If there are packets in buffer waiting to be sent out
            if srcip in self.buffer.keys():

		##DEBUG FROM HERE

                log.debug("A packet is detected in buffer!")
                out_port = self.routing_table[self.buffer[srcip]['DestinationNetwork']]['Port']
                ip_packet = self.buffer[srcip]['IP_Packet']
		source_ip = str(ip_packet.srcip)
                etherFrame = ethernet()
                etherFrame.type = etherFrame.IP_TYPE
                etherFrame.src = EthAddr(self.arp_table[self.routing_table[self.buffer[srcip]['DestinationNetwork']]['RouterInterface']])
                etherFrame.dst = EthAddr(self.arp_table[srcip])
                etherFrame.payload = ip_packet
                self.resend_packet(etherFrame, out_port)
		
		self.push_flow_label(source_ip,srcip,out_port)
                
                self.buffer.pop(srcip)

    def ICMP_Handler(self, packet, packet_in):
        ethernet_frame = packet
        ip_packet = packet.payload

        icmp_request_packet = ip_packet.payload

        # ICMP Echo Request (8) -> ICMP Echo Reply (0)
        if icmp_request_packet.type == 8:
            icmp_echo_reply_packet = icmp()
            icmp_echo_reply_packet.code = 0
            icmp_echo_reply_packet.type = 0
            icmp_echo_reply_packet.payload = icmp_request_packet.payload

            ip = ipv4()
            ip.srcip = ip_packet.dstip
            ip.dstip = ip_packet.srcip
            ip.protocol = ipv4.ICMP_PROTOCOL
            ip.payload = icmp_echo_reply_packet

            ether = ethernet()
            ether.type = ethernet.IP_TYPE
            ether.src = ethernet_frame.dst
            ether.dst = ethernet_frame.src
            ether.payload = ip

            self.resend_packet(ether, packet_in.in_port)
            log.debug("ICMP ECHO REPLY SENT!")
    #def push_qos_flows(destination_ip):

    def checkRoutableDestination(self, destination_ip):
	routable = False
        for netaddr in self.routing_table:
            destination_network = netaddr
            if IPAddress(destination_ip) in IPNetwork(destination_network):
                log.debug('PACKET IS ROUTABLE!')
                routable = True
                break
	return routable, destination_network

    def _handle_PacketIn(self, event):
        """
        Handles packet in messages from the switch.
        """
        etherFrame = event.parsed  # This is the parsed packet data.

        if not etherFrame.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp  # The actual ofp_packet_in message.

        # Add the new MAC into CAM table
        if str(etherFrame.src) not in self.mac_to_port:
            log.debug('Adding %s into CAM' % str(etherFrame.src))
            self.mac_to_port[str(etherFrame.src)] = packet_in.in_port

        # ARP
        if etherFrame.type == ethernet.ARP_TYPE:
            log.debug('RECEIVED: EtherType -> ARP')
            self.ARP_Handler(etherFrame, packet_in)
        # IP
        elif etherFrame.type == ethernet.IP_TYPE:
            log.debug('RECEIVED: EtherType -> IP')

            # Extract IP Packet from Ethernet Frame
            ip_packet = etherFrame.payload

            # Routable?
            destination_ip = str(ip_packet.dstip)
	    source_ip = str(ip_packet.srcip)

	    log.debug('DESTIP of THE CURRENT PACKET: '+destination_ip+' FROM SRCIP '+source_ip)

	    routable, destination_network = self.checkRoutableDestination(destination_ip)

            if routable:
                # Destined for router
                if self.routing_table[str(destination_network)]['RouterInterface'] == destination_ip:
                    if ip_packet.protocol == ipv4.ICMP_PROTOCOL:
                        log.debug('ICMP ECHO -> ROUTER INTERFACE')
                        self.ICMP_Handler(etherFrame, packet_in)

		    elif ip_packet.protocol == 0x11:
			log.debug('UDP PACKET DETECTED!')
	
			udp_packet = ip_packet.payload
			print "\nRECEIVED UDP PACKET IN PORT NUMBER : "+str(udp_packet.dstport)
			
			if udp_packet.dstport == 9999:	
				print "\nUDP PAYLOAD : "+str(udp_packet.payload)
				self.handleBandwidthRequest(udp_packet.payload)
			
			
                # Check if any there's any routable networks for the destination IP
                elif routable:
                    # Route the packet to it's respective ports
                    output_port = self.routing_table[destination_network]['Port']

                    # ARP if host MAC Address is not present
                    if destination_ip not in self.arp_table:
                        # Push frame to buffer
                        self.buffer[destination_ip] = {'IP_Packet': ip_packet, 'DestinationNetwork': destination_network}

			self.ARPResolve(destination_ip, destination_network, output_port)

                    if destination_ip in self.arp_table:
			if destination_ip == "10.0.2.100":
				print "\n--DETECTED NEW PACKET TO APPLY QOS FLOW. PROCEEDING ...--"
			else:
				print "\n--DETECTED NEW PACKET TO APPLY NORMAL FLOW. PROCEEDING ...--"
			self.buffer[destination_ip] = {'IP_Packet': ip_packet, 'DestinationNetwork': destination_network}
			self.push_flow_label(source_ip,destination_ip,output_port)
			print "\n--FLOW LABEL SUCCESSFULLY PUSHED FOR NEWLY DETECTED PACKET!--"

                        etherFrame.src = EthAddr(self.arp_table[self.routing_table[destination_network]['RouterInterface']])
                        etherFrame.dst = EthAddr(self.arp_table[destination_ip])
                        self.resend_packet(etherFrame, output_port)
            # ICMP Destination Unreachable for non-routable networks
            else:
		#if source_ip != '0.0.0.0':
		log.debug('PACKET IS NOT ROUTABLE for IPdest'+str(ip_packet.dstip)+' from IPsrc '+str(ip_packet.srcip))
		ethernet_frame = etherFrame
		ip_packet = etherFrame.payload
		icmp_request_packet = ip_packet.payload
		icmp_echo_reply_packet = icmp()
		icmp_echo_reply_packet.code = 0
		icmp_echo_reply_packet.type = 3
		icmp_echo_reply_packet.payload = icmp_request_packet.payload

		ip = ipv4()
		ip.srcip = ip_packet.dstip
		ip.dstip = ip_packet.srcip
		ip.protocol = ipv4.ICMP_PROTOCOL
		ip.payload = icmp_echo_reply_packet

		ether = ethernet()
		ether.type = ethernet.IP_TYPE
		ether.src = ethernet_frame.dst
		ether.dst = ethernet_frame.src
		ether.payload = ip

                self.resend_packet(ether, packet_in.in_port)
                log.debug("ICMP DESTINATION UNREACHABLE SENT")
		log.debug("Ignoring packet with src ip 0.0.0.0")

def launch():
    """
    Starts the component
    """
    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        global s1_dpid, s2_dpid 
	print("ConnectionUp: ", dpid_to_str(event.connection.dpid))
	#remember the connection dpid for switch 
	for m in event.connection.features.ports:
		if m.name == "s1-eth1": 
			s1_dpid = event.connection.dpid 
			print("s1_dpid=", s1_dpid)
			print("Assigning router functionality to S1 with dpid", s1_dpid)
			Router(event.connection,s1_dpid)
		elif m.name == "s2-eth1":
			s2_dpid = event.connection.dpid
			print("s2_dpid=", s2_dpid) 
			print("Assigning switch functionality to S2 with dpid", s2_dpid)
			Switch(event.connection,s2_dpid)
		elif m.name == "s3-eth1":
			s3_dpid = event.connection.dpid
			print("s3_dpid=", s3_dpid) 
			print("Assigning switch functionality to S2 with dpid", s3_dpid)
			Switch(event.connection,s3_dpid)
    pox.core.core.openflow.addListenerByName("ConnectionUp", start_switch)
