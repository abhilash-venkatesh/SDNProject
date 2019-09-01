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

log = pox.core.getLogger()

s1_dpid=0 
s2_dpid=0

class Router(object):
    def __init__(self, connection):
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)

        # Buffer for packets waiting for ARP
        self.buffer = {}

        # Use this table to keep track of which ethernet address is on
        # which switch port (keys are MACs, values are ports).
        self.mac_to_port = {}

        # ARP Table
        self.arp_table = {}
        self.arp_table['10.0.1.1'] = 'AA:BB:CC:DD:EE:01'
        self.arp_table['10.0.2.1'] = 'AA:BB:CC:DD:EE:02'
        self.arp_table['10.0.3.1'] = 'AA:BB:CC:DD:EE:03'
	self.arp_table['10.0.4.1'] = 'AA:BB:CC:DD:EE:04'

        # Route default flows for ICMP traffic destined to Router Interfaces
        for dest in self.arp_table.keys():
            msg = of.ofp_flow_mod()
            msg.priority = 100
            msg.match.dl_type = ethernet.IP_TYPE
            msg.match.nw_proto = ipv4.ICMP_PROTOCOL
            msg.match.nw_dst = IPAddr(dest)
            msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
            self.connection.send(msg)

        self.routing_table = {}
        self.routing_table['10.0.1.0/24'] = {'Port': 1, 'RouterInterface':'10.0.1.1'}
        self.routing_table['10.0.2.0/24'] = {'Port': 2, 'RouterInterface':'10.0.2.1'}
        self.routing_table['10.0.3.0/24'] = {'Port': 3, 'RouterInterface':'10.0.3.1'}
	self.routing_table['10.0.4.0/24'] = {'Port': 4, 'RouterInterface':'10.0.4.1'}

    def resend_packet(self, packet_in, out_port):
        """
        Instructs the switch to resend a packet that it had sent to us.
        "packet_in" is the ofp_packet_in object the switch had sent to the
        controller due to a table-miss.
        """
        msg = of.ofp_packet_out()
        msg.data = packet_in.pack()

        # Add an action to send to the specified port
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)

        # Send message to switch
        self.connection.send(msg)

    def ARP_Handler(self, packet, packet_in):
        log.debug("!LOG! S1 : ARP FRAME RECEIVED FROM %s" % packet_in.in_port)

        if packet.payload.opcode == arp.REQUEST:
            log.debug("!LOG! S1 : IT'S AN ARP REQUEST!")

            arp_payload = packet.payload
            arp_request_ip = str(arp_payload.protodst)
            if arp_request_ip in self.arp_table:

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
                log.debug("!LOG! S1 : ARP REPLY SENT!")

        elif packet.payload.opcode == arp.REPLY:
            log.debug("!LOG! S1 : IT'S AN ARP REPLY!")

            arp_payload = packet.payload
            hwsrc = str(arp_payload.hwsrc)
            srcip = str(arp_payload.protosrc)
            if srcip not in self.arp_table:
                self.arp_table[srcip] = hwsrc
                self.mac_to_port[hwsrc] = packet_in.in_port
                log.debug("!LOG! S1 : %s %s INSTALLED TO CAM TABLE" % (srcip, hwsrc))

            # If there are packets in buffer waiting to be sent out
            if srcip in self.buffer.keys():
                print 'Packet waiting in buffer!'
                out_port = self.routing_table[self.buffer[srcip]['DestinationNetwork']]['Port']
                ip_packet = self.buffer[srcip]['IP_Packet']
                etherFrame = ethernet()
                etherFrame.type = etherFrame.IP_TYPE
                etherFrame.src = EthAddr(self.arp_table[self.routing_table[self.buffer[srcip]['DestinationNetwork']]['RouterInterface']])
                etherFrame.dst = EthAddr(self.arp_table[srcip])
                etherFrame.payload = ip_packet
                self.resend_packet(etherFrame, out_port)

                msg = of.ofp_flow_mod()
                print self.buffer[srcip]['DestinationNetwork']
                msg.priority = 10
                msg.match.dl_type = ethernet.IP_TYPE
                msg.match.nw_proto = ipv4.ICMP_PROTOCOL
                msg.match.set_nw_dst(self.buffer[srcip]['DestinationNetwork'])
                # msg.match.nw_dst = IPAddr(srcip)
                msg.actions.append(of.ofp_action_dl_addr.set_src(EthAddr(self.arp_table[self.routing_table[self.buffer[srcip]['DestinationNetwork']]['RouterInterface']])))
                msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(self.arp_table[srcip])))
                msg.actions.append(of.ofp_action_output(port=out_port))
                self.connection.send(msg)
                log.debug("!LOG! S1 : Flow mod for destination network %s sent!", self.buffer[srcip]['DestinationNetwork'])
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
            log.debug("!LOG! S1 : ICMP ECHO REPLY SENT!")

    def _handle_PacketIn(self, event):
        """
        Handles packet in messages from the switch.
        """
        etherFrame = event.parsed  # This is the parsed packet data.

        if not etherFrame.parsed:
            log.warning("!LOG WARN! S1 : Ignoring incomplete packet")
            return

        packet_in = event.ofp  # The actual ofp_packet_in message.

        # Add the new MAC into CAM table
        if str(etherFrame.src) not in self.mac_to_port:
            log.debug('!LOG! S1 : Adding %s into CAM, recv from %s' % (str(etherFrame.src), str(packet_in.in_port)))
            self.mac_to_port[str(etherFrame.src)] = packet_in.in_port

        # ARP
        if etherFrame.type == ethernet.ARP_TYPE:
            log.debug('!LOG! S1 : RECEIVED: EtherType -> ARP')
            self.ARP_Handler(etherFrame, packet_in)
        # IP
        elif etherFrame.type == ethernet.IP_TYPE:
            log.debug('!LOG! S1 : RECEIVED: EtherType -> IP')

            # Extract IP Packet from Ethernet Frame
            ip_packet = etherFrame.payload

            # Routable?
            destination_ip = str(ip_packet.dstip)

            routable = False
            for netaddr in self.routing_table:
                destination_network = netaddr
                if IPAddress(destination_ip) in IPNetwork(destination_network):
                    log.debug('!LOG! S1 : PACKET IS ROUTABLE!')
                    routable = True
                    break

            if routable:
                # Destined for router
                if self.routing_table[str(destination_network)]['RouterInterface'] == destination_ip:
                    if ip_packet.protocol == ipv4.ICMP_PROTOCOL:
                        log.debug('!LOG! S1 : ICMP ECHO -> ROUTER INTERFACE')
                        self.ICMP_Handler(etherFrame, packet_in)

                # Check if any there's any routable networks for the destination IP
                elif routable:
                    # Route the packet to it's respective ports
                    output_port = self.routing_table[destination_network]['Port']

                    # ARP if host MAC Address is not present
                    if destination_ip not in self.arp_table:
                        # Push frame to buffer
                        self.buffer[destination_ip] = {'IP_Packet': ip_packet, 'DestinationNetwork': destination_network}

                        # Construct ARP Packet
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

                    if destination_ip in self.arp_table:
                        etherFrame.src = EthAddr(self.arp_table[self.routing_table[destination_network]['RouterInterface']])
                        etherFrame.dst = EthAddr(self.arp_table[destination_ip])
                        self.resend_packet(etherFrame, output_port)
            # ICMP Destination Unreachable for non-routable networks
            else:
                log.debug('!LOG! S1 : PACKET IS NOT ROUTABLE!')
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
                log.debug("!LOG! S1 : ICMP DESTINATION UNREACHABLE SENT")

class Switch(object):
  def __init__ (self, connection):
    self.connection = connection
    connection.addListeners(self)

    self.mac_to_port = {}

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
        log.debug("!LOG! S2 : Learning that " + str(packet.src) + " is attached at port " + str(packet_in.in_port))
        self.mac_to_port[packet.src] = packet_in.in_port
    if packet.dst in self.mac_to_port:
      log.debug("!LOG! S2 : " + str(packet.dst) + " destination known. only send message to it")
      self.resend_packet(packet_in, self.mac_to_port[packet.dst])
    else:
      log.debug("!LOG! S2 : " + str(packet.dst) + " not known, resend to everybody")
      self.resend_packet(packet_in, of.OFPP_ALL)


  def _handle_PacketIn (self, event):
    packet = event.parsed
    if not packet.parsed:
      log.warning("!LOG! S2 : Ignoring incomplete packet")
      return

    packet_in = event.ofp

    #self.act_like_hub(packet, packet_in)
    self.act_like_switch(packet, packet_in)


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
			Router(event.connection)
		elif m.name == "s2-eth1":
			s2_dpid = event.connection.dpid
			print("s2_dpid=", s2_dpid) 
			print("Assigning switch functionality to S2 with dpid", s1_dpid)
			Switch(event.connection)
    pox.core.core.openflow.addListenerByName("ConnectionUp", start_switch)
