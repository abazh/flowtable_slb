from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
import logging
import random
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import arp
from ryu.lib.packet import icmp
from ryu.controller.handler import DEAD_DISPATCHER
from ryu.lib import hub
import json
import time

#Pingall requried before trying load balancing functionality

class loadbalancer(app_manager.RyuApp):
    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    
    def __init__(self, *args, **kwargs):
        super(loadbalancer, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.serverlist = []
        self.serverlist.append({'ip':"10.0.0.1", 'mac':"00:00:00:00:00:01", 'server_port' : "1"})
        self.serverlist.append({'ip':"10.0.0.2", 'mac':"00:00:00:00:00:02", 'server_port' : "2"})
        self.serverlist.append({'ip':"10.0.0.3", 'mac':"00:00:00:00:00:03", 'server_port' : "3"})
        self.virtual_lb_ip = "10.0.0.100"
        self.virtual_lb_mac = "AB:BC:CD:EF:F1:12"
        self.serverNumber = 0
        self.logger.info("Initialized new Object instance data")
        
        self.flow_monitor = 0
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

        self.ctemp = []
        self.dtemp = []
        self.ptemp = []
        self.btemp = []
        self.cookie_temp = 0
        self.longest_duration = 0
        self.cookie_idx0 = 0xffffffffffffffff
        self.clongest_dur = 0xffffffffffffffff

        

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

		# install table-miss flow entry
		#
		# We specify NO BUFFER to max_len of the output action due to
		# OVS bug. At this moment, if we specify a lesser number, e.g.,
		# 128, OVS will send Packet-In with invalid buffer_id and 
		# truncated packet data. In that case, we cannot output packets
		# correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        # self.logger.info("Set Config data for new Object Instance")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        # self.logger.info("Now adding flow")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, 
                                    priority=priority, match=match, 
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
		
        datapath.send_msg(mod)
        # self.logger.info("Done adding flows")
    
    def delete_flow(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        cookie = self.cookie_temp
        cookie_mask = self.cookie_temp
        table_id = 0
        idle_timeout = hard_timeout = 0
        priority = 32768
        buffer_id = ofproto.OFP_NO_BUFFER
        
        req = parser.OFPFlowMod(datapath, cookie, cookie_mask,
                                    table_id, ofproto.OFPFC_DELETE,
                                    idle_timeout, hard_timeout,
                                    priority, buffer_id,
                                    ofproto.OFPP_ANY, ofproto.OFPG_ANY,
                                    ofproto.OFPFF_SEND_FLOW_REM,)
        datapath.send_msg(req)
        print("flow dengan cookie " + hex(self.cookie_temp) + " telah dihapus")

    def handle_arp_for_server(self, dmac, dip):
        self.logger.info("Handling ARP Reply for virtual Server IP")
		#handle arp request for virtual Server IP
		#checked Wireshark for sample pcap for arp-reply
		#build arp packet - format source web link included in reference
        hrdw_type = 1 #Hardware Type: ethernet 10mb
        protocol = 2048 #Layer 3 type: Internet Protocol
        hrdw_add_len = 6 # length of mac
        prot_add_len = 4 # lenght of IP
        opcode = 2 # arp reply
        server_ip = self.virtual_lb_mac #sender address
        server_mac = self.virtual_lb_ip #sender IP
        arp_target_mac = dmac #target MAC
        arp_target_ip = dip #target IP
		
        ether_type = 2054 #ethertype ARP
		
        pack = packet.Packet()
        eth_frame = ethernet.ethernet(dmac, server_ip, ether_type)
        arp_rpl_frame = arp.arp(hrdw_type, protocol, hrdw_add_len, prot_add_len, opcode, server_ip, server_mac, arp_target_mac, arp_target_ip)
        pack.add_protocol(eth_frame)
        pack.add_protocol(arp_rpl_frame)
        pack.serialize()
        # self.logger.info("Done handling ARP Reply")
        return pack
		
	
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # self.logger.info("Entered main mode event handling")
        	# If you hit this you might want to increase
        	# the "miss_send_length" of your switch
        # if ev.msg.msg_len < ev.msg.total_len:
            # self.logger.debug("packet truncated: only %s of %s bytes", ev.msg.msg_len, ev.msg.total_len)
        if self.serverNumber == 3:
            self.serverNumber = 0
							  
        # self.logger.info("Will print data now")					  
		#print event data
		
        #fetch all details of the event
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]


        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)		

		# learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port       		
        # self.logger.info("Ether Type: %s", eth.ethertype)
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
			# ignore lldp packet
            return
			
        if eth.ethertype == 2054:
            arp_head = pkt.get_protocols(arp.arp)[0]
            if arp_head.dst_ip == self.virtual_lb_ip:
				#dmac and dIP for ARP Reply
                a_r_ip = arp_head.src_ip
                a_r_mac = arp_head.src_mac
                arp_reply = self.handle_arp_for_server(a_r_mac, a_r_ip)
                actions = [parser.OFPActionOutput(in_port)]
                buffer_id = msg.buffer_id #id assigned by datapath - keep track of buffered packet
                port_no = ofproto.OFPP_ANY #for any port number
                data = arp_reply.data
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id, in_port=port_no, actions=actions, data=data)
                datapath.send_msg(out)
                # self.logger.info("ARP Request handled")				
                return
            else:
                dst = eth.dst
                src = eth.src

                dpid = datapath.id
                self.mac_to_port.setdefault(dpid, {})

                # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

                # learn a mac address to avoid FLOOD next time.
                self.mac_to_port[dpid][src] = in_port

                if dst in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][dst]
                else:
                    out_port = ofproto.OFPP_FLOOD
				
                actions = [parser.OFPActionOutput(out_port)]

                # install a flow to avoid packet_in next time
                if out_port != ofproto.OFPP_FLOOD:
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                    # verify if we have a valid buffer_id, if yes avoid to send both
                    # flow_mod & packet_out
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1, match, actions)
				
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data
					
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
                return
        
        try:
            if pkt.get_protocols(icmp.icmp)[0]:
		
			#if ip_head.proto == inet.IPPROTO_ICMP:
                dst = eth.dst
                src = eth.src

                dpid = datapath.id
                self.mac_to_port.setdefault(dpid, {})

                # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

       			# learn a mac address to avoid FLOOD next time.
                self.mac_to_port[dpid][src] = in_port
                
                if dst in self.mac_to_port[dpid]:
                    out_port = self.mac_to_port[dpid][dst]
                else:
                    out_port = ofproto.OFPP_FLOOD
	
                actions = [parser.OFPActionOutput(out_port)]

        		# install a flow to avoid packet_in next time
                if out_port != ofproto.OFPP_FLOOD:
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            		# verify if we have a valid buffer_id, if yes avoid to send both
            		# flow_mod & packet_out
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1, match, actions)
				
                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
                return

        except:
            pass
		

        ip_head = pkt.get_protocols(ipv4.ipv4)[0]
        # tcp_head = pkt.get_protocols(tcp.tcp)[0]

		# pingall before executing load balancer functionality
        # self.logger.info("Trying to map ports and server list")
        for server in self.serverlist:
            try:
                if server['mac'] in self.mac_to_port[dpid]:
                    try:
                        server['server_port'] = self.mac_to_port[dpid][server['mac']]
                        # self.logger.info("Port mapping successful for Server: %s ---check--- %s", server['ip'], server['server_port'])
                    except Exception as e:
                        self.logger.info("Internal Exception: %s", e)
            except Exception as e:
                self.logger.info("External Exception: %s", e)

        # self.logger.info("If there is no failure of mapping then we are good to go...")
		#server choice for round robin style
		
		
        choice_ip = self.serverlist[self.serverNumber]['ip']
        choice_mac = self.serverlist[self.serverNumber]['mac']
        choice_server_port = self.serverlist[self.serverNumber]['server_port']
        # self.logger.info("Server Choice details: \tIP is %s\tMAC is %s\tPort is %s", choice_ip, choice_mac, choice_server_port)
		
		
		
        # self.logger.info("Redirecting data request packet to one of the server list")
		#Redirecting data request packet to Server
        match = parser.OFPMatch(in_port=in_port, eth_type=eth.ethertype, eth_src=eth.src, eth_dst=eth.dst, ip_proto=ip_head.proto, ipv4_src=ip_head.src, ipv4_dst=ip_head.dst)
        # self.logger.info("Data request being sent to Server: IP: %s, MAC: %s", choice_ip, choice_mac)
        actions = [parser.OFPActionSetField(eth_dst=choice_mac), parser.OFPActionSetField(ipv4_dst=choice_ip), parser.OFPActionOutput(choice_server_port)]
        instruction1 = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        cookie = random.randint(0, 0xffffffffffffffff)
        flow_mod = parser.OFPFlowMod(datapath=datapath, match=match, idle_timeout=0, instructions=instruction1, buffer_id = msg.buffer_id, cookie=cookie)
        datapath.send_msg(flow_mod)

        # self.logger.info("Redirection done...1")
        # self.logger.info("Redirecting data reply packet to the host")
		#Redirecting data reply to respecitve Host
        match = parser.OFPMatch(in_port=choice_server_port, eth_type=eth.ethertype, eth_src=choice_mac, eth_dst=eth.src, ip_proto=ip_head.proto, ipv4_src=choice_ip, ipv4_dst=ip_head.src)
        # self.logger.info("Data reply coming from Server: IP: %s, MAC: %s", choice_ip, choice_mac)
        actions = [parser.OFPActionSetField(eth_src=self.virtual_lb_mac), parser.OFPActionSetField(ipv4_src=self.virtual_lb_ip), parser.OFPActionOutput(in_port) ]

        instruction2 = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        cookie = random.randint(0, 0xffffffffffffffff)

        flow_mod2 = parser.OFPFlowMod(datapath=datapath, match=match, idle_timeout=60, instructions=instruction2, cookie=cookie)
        datapath.send_msg(flow_mod2)

        self.serverNumber = self.serverNumber + 1
        # self.logger.info("Redirecting done...2")



    #Method untuk melakukan monitoring flow table setiap x detik
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(5)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)
    
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        ctemp_idx = 0
        
        self.flow_monitor = len(body)
        print("Flow Entry saat ini : " + str(self.flow_monitor))
        self.logger.info('  cookie     '
                             '       duration        '
                             ' packets     bytes')
        self.logger.info('---------------- '
                             '----------------- '
                             '----------  ----------')
        
        flow_table = ev.msg.to_jsondict()
        for i in range (self.flow_monitor):
            # print(i)
            cookie = (flow_table["OFPFlowStatsReply"]["body"][i]["OFPFlowStats"]["cookie"])
            duration = (flow_table["OFPFlowStatsReply"]["body"][i]["OFPFlowStats"]["duration_sec"])
            packet_count = (flow_table["OFPFlowStatsReply"]["body"][i]["OFPFlowStats"]["packet_count"])
            byte_count = (flow_table["OFPFlowStatsReply"]["body"][i]["OFPFlowStats"]["byte_count"])
            # print('{:016x} {:8d} {:15d} {:12d}'.format(cookie, duration, packet_count, byte_count))
            
            if not cookie in self.ctemp:
                self.ctemp.append(cookie)
                self.dtemp.append(duration)
                self.ptemp.append(packet_count)
                self.btemp.append(byte_count)
                print('{:016x} {:8d} {:15d} {:12d}'.format(cookie, duration, packet_count, byte_count))
            elif cookie in self.ctemp and cookie !=0:
                ctemp_idx = self.ctemp.index(cookie)
                if byte_count > self.btemp[ctemp_idx] and packet_count > self.ptemp[ctemp_idx]:
                    self.ctemp[ctemp_idx] = cookie
                    self.btemp[ctemp_idx] = byte_count
                    self.dtemp[ctemp_idx] = duration
                    self.ptemp[ctemp_idx] = packet_count
                    #print("Flow Entry saat ini : " + str(self.flow_monitor))
                    print('{:016x} {:8d} {:15d} {:12d}'.format(cookie, duration, packet_count, byte_count))
                elif byte_count == self.btemp[ctemp_idx]:
                    if self.flow_monitor > 50:
                        print("hapus flow dengan cookie " + hex(cookie))
                        self.cookie_temp = cookie
                        # call function delete_flow(cookie)
                        self.delete_flow(ev)
                    else:
                        print('{:016x} {:8d} {:15d} {:12d}'.format(cookie, duration, packet_count, byte_count))                
                else:
                    #print("Flow Entry saat ini : " + str(self.flow_monitor))
                    print('{:016x} {:8d} {:15d} {:12d}'.format(cookie, duration, packet_count, byte_count))
            
            #function to check longest duration
            if self.longest_duration < self.dtemp[ctemp_idx]:
                self.longest_duration = self.dtemp[ctemp_idx]
                self.clongest_dur = self.ctemp[ctemp_idx]
            else:
                self.longest_duration = self.longest_duration
                # print("longest duration : " + str(self.longest_duration ))
                self.longest_duration = 0
                # print(hex(self.cookie_idx0))
                # print(hex(self.clongest_dur))
                if self.flow_monitor >= (0.9*50):
                    print("Flow Table PENUH!!!! Perlu dilakukan penghapusan paksa !!")
                    self.cookie_temp = self.clongest_dur
                    print("menghapus flow entry dengan 'total duration' paling lama . . . ." + hex(self.clongest_dur))
                    self.delete_flow(ev)
