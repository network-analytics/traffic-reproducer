#
# Copyright(c) 2023 Swisscom (Schweiz) AG
# Authors: Marco Tollini, Leonardo Rodoni
# Distributed under the MIT License (http://opensource.org/licenses/MIT)
#

# External Libraries
import sys
import logging
import pathlib
import os
from time import time, sleep
from scapy.all import Ether, IP, IPv6, TCP, Raw, raw, rdpcap, PacketList, EDecimal
from scapy.layers.l2 import *
from scapy.contrib.mpls import *

# Internal Libraries
from pcap_utils.scapy_helpers import get_layers, tcp_fragment, tcp_build
from pcap_utils.filter import filter_generator, bmp_msg_filter_generator
from pcap_utils.bmp_scapy.bmp import *

# Class for storing BMP packets belonging to a TCP session
class BMPSession:
    def __init__(self, ip_ver, ip_src, ip_dst):
        self.ip_ver = ip_ver
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.bmp_packets = []

class BMPProcessing:

    def __init__(self, pcap_file, bmp_selectors):

        #   "ip_src": { ...
        #       "bmp_version": 
        #       "sysDescr": 
        #       "sysName": 
        #       "BGP_peers": {"Peer_BGP_Id":
        #                                     { "bgp_version": 
        #                                       "as_number": 
        #                                       "route_monitoring_counter":
        #                                       "stats_counter":    },
        #                        ... }
        #               ... }
        self.info = {}

        # List of BMPSession() instances
        self.bmp_sessions = [] 

        self.bmp_selectors = bmp_selectors

        # Extract BMP packets by TCP session and populate self.bmp_sessions
        packets = self.__bmp_extract(pcap_file)
        packets = self.__bmp_sessions_cleanup(packets)
        self.__bmp_sessions_defragment(packets)   
        
        # Some more filtering on BMP layers
        self.__bmp_apply_additional_filters()



    def __bmp_extract(self, pcap_file):
        # Extract BMP packets with filter selectors

        packets_new = []

        # Load pcap in memory
        packets = rdpcap(pcap_file)
        logging.info(f"Size of packets: {len(packets)}") 
        
        # Generate filter from selectors
        logging.debug(f"bmp_selectors: {self.bmp_selectors}")
        proto_filter = filter_generator(self.bmp_selectors)

        for packet in packets:
            if proto_filter(packet):
                packets_new.append(packet)

        logging.debug(f"Size of filtered packets [BMP selector]: {len(packets_new)}")

        return PacketList(packets_new)

    def __bmp_sessions_cleanup(self, packets):
        # Select clean BMP sessions only
        #  --> discard all messages before BMP INIT is received
        #  --> discard incomplete sessions (i.e. without any INIT)
        #  --> discard too small packets (i.e. packets smaller than 6bytes)

        packets_new = []
        tcp_sessions = packets.sessions()
        
        for session_id, plist in tcp_sessions.items():
            keep_session = False
            
            for packet in plist:
                bmp_packet = packet[TCP].payload

                # Check if we have an INIT message
                if len(bmp_packet) >= 6 and raw(bmp_packet)[5] == 4: 
                    keep_session = True
                    packets_new.append(packet)
                else:
                    # Keep only packets after OPEN received
                    if keep_session and len(bmp_packet) >= 6: 
                        packets_new.append(packet)

        return PacketList(packets_new)

    def __bmp_sessions_defragment(self, packets):
        # Quick & dirty BMP message defragment (not thoroughly tested)

        tcp_sessions = packets.sessions()
        tcp_port = self.bmp_selectors['tcp']['dport']
        
        # Process all BMP sessions
        for session_id, plist in tcp_sessions.items():

            logging.debug(f"Defragmenting BMP from TCP session [ID = {session_id}]")
            #print(plist.summary())

            # Get IP addresses to later reconstruct packet headers
            first_pkt = plist[0]
            if IP in first_pkt:
                ip_ver = 4
                ip_src = first_pkt[IP].src
                ip_dst = first_pkt[IP].dst
            elif IPv6 in  first_pkt:
                ip_ver = 6
                ip_src = first_pkt[IPv6].src
                ip_dst = first_pkt[IPv6].dst

            bmp_packets_temp = []
            bmp_session = BMPSession(ip_ver, ip_src, ip_dst)            

            # Defragmenting BMP session
            reassembled_raw = None
            for packet in plist:

                #packet.show()
                
                if packet[TCP].payload.name == "Raw":
                    if not reassembled_raw:
                        reassembled_raw = raw(bmp_packets_temp.pop()) + raw(packet[TCP].payload)
                    else:
                        reassembled_raw += raw(packet[TCP].payload)

                else:
                    if reassembled_raw:
                        bmp_packets_temp.append(BMP(reassembled_raw))
                        reassembled_raw = None
                        
                    bmp_packets_temp.append(packet[TCP].payload)

            # Append last packet if we have remaining raw payload
            if reassembled_raw:
                bmp_packets_temp.append(BMP(reassembled_raw))

            # Split up and get single BMP messages
            for bmp_packet in bmp_packets_temp:

                raw_bmp_packet = raw(bmp_packet)
                bmp_hdr = BMP(raw_bmp_packet[:6])

                while bmp_hdr.getlayer(BMPHeader):

                    #bmp_hdr.show()

                    length = bmp_hdr[BMPHeader].len
                    #print("length=", length)
                    bmp_session.bmp_packets.append(BMP(raw_bmp_packet[:length]))

                    raw_bmp_packet = raw_bmp_packet[length:]
                    bmp_hdr = BMP(raw_bmp_packet[:6])
                    
            self.bmp_sessions.append(bmp_session)

    def __bmp_apply_additional_filters(self):
        # Apply more advanced filters if provided in proto selectors, 
        # i.e. BMP msg type

        # Generate filter from selectors
        proto_filter = bmp_msg_filter_generator(self.bmp_selectors)

        for i in range(len(self.bmp_sessions)):

            bmp_packets_new = []
            for bmp_packet in self.bmp_sessions[i].bmp_packets:
                if proto_filter(bmp_packet):
                    bmp_packets_new.append(bmp_packet)
            
            self.bmp_sessions[i].bmp_packets = bmp_packets_new


    def register_bgp_open(self, ip_src, peer_bgp_id, bgp_packet):

        self.info[str(ip_src)]['BGP_Peers'][str(peer_bgp_id)]['bgp_version'] = bgp_packet[BGPOpen].version

        # TODO: check capabilities if necessary

        self.info[str(ip_src)]['BGP_Peers'][str(peer_bgp_id)]['route_monitoring_counter'] = 0
        self.info[str(ip_src)]['BGP_Peers'][str(peer_bgp_id)]['stats_counter'] = 0

    def register_bmp_peerup(self, ip_src, bmp_packet):

        peer_bgp_id = bmp_packet[PerPeerHeader].peer_bgp_id

        #bmp_packet.show()
        #get_layers(bmp_packet, do_print=True, layer_limit=10)

        if str(peer_bgp_id) not in self.info[str(ip_src)]['BGP_Peers'].keys():
            
            self.info[str(ip_src)]['BGP_Peers'][str(peer_bgp_id)] = {"as_number": bmp_packet[PerPeerHeader].peer_asn}
            self.register_bgp_open(ip_src, peer_bgp_id, bmp_packet)

    def register_bmp_init(self, ip_src, bmp_packet):
        self.info[str(ip_src)]['bmp_version'] = bmp_packet[BMPHeader].version

        for tlv in bmp_packet[BMPHeader].information:
            if tlv.type == 1:
                self.info[str(ip_src)]['sysDescr'] = tlv.value.decode()
            elif tlv.type == 2:
                self.info[str(ip_src)]['sysName'] = tlv.value.decode()
        
        # Initialize BGP Peers Dict
        self.info[str(ip_src)]['BGP_Peers'] = {}

    def bmp_session_info(self):
        for bmp_session in self.bmp_sessions:
            if str(bmp_session.ip_src) not in self.info.keys():
                self.info[str(bmp_session.ip_src)] = {}
            
            for bmp_packet in bmp_session.bmp_packets:

                # DEBUG PRINT:
                #get_layers(bmp_packet, do_print=True, layer_limit=5)

                # BMP INIT
                if bmp_packet.haslayer(BMPInitiation):
                    self.register_bmp_init(bmp_session.ip_src, bmp_packet)

                # BMP PEER UP
                elif bmp_packet.haslayer(BMPPeerUp):
                    self.register_bmp_peerup(bmp_session.ip_src, bmp_packet)

                # BMP ROUTE-MONITORING
                elif bmp_packet.haslayer(BMPRouteMonitoring):
                    self.info[str(bmp_session.ip_src)]['BGP_Peers'] \
                             [str(bmp_packet[PerPeerHeader].peer_bgp_id)]['route_monitoring_counter'] += 1

                # BMP STATS
                elif bmp_packet.haslayer(BMPStats):
                    self.info[str(bmp_session.ip_src)]['BGP_Peers'] \
                             [str(bmp_packet[PerPeerHeader].peer_bgp_id)]['stats_counter'] += 1

                # BMP PEER DOWN & OTHERS (TODO: implement if necessary...)

    def tcp_build_wrapper(self):
        # - groups messages by msg_type
        # - calls tcp_build helper to construct TCP segments s.t. MTU ~= 1500
        # - calls tcp_fragment to make sure MTU < 1500
        tcp_packets = []
        
        for bmp_session in self.bmp_sessions:
            payloads = []
            msg_type = 999

            tcp_seq_nr = 1
            for bmp_packet in bmp_session.bmp_packets:
                if (bmp_packet[BMPHeader].type != msg_type and payloads):
                    tmp_tcp_packets,tcp_seq_nr = tcp_build(payloads, bmp_session.ip_ver,
                                                          bmp_session.ip_src, bmp_session.ip_dst,
                                                          self.bmp_selectors['tcp']['dport'],
                                                          tcp_seq_nr)
                    tcp_packets += tmp_tcp_packets
                    payloads = [bmp_packet]
                    msg_type = bmp_packet[BMPHeader].type
                else:
                    payloads.append(bmp_packet)

            if (payloads): 
                tmp_tcp_packets,tcp_seq_nr = tcp_build(payloads, bmp_session.ip_ver,
                                                      bmp_session.ip_src, bmp_session.ip_dst,
                                                      self.bmp_selectors['tcp']['dport'],
                                                      tcp_seq_nr)
                tcp_packets += tmp_tcp_packets

        tcp_packets = tcp_fragment(PacketList(tcp_packets), self.bmp_selectors['tcp']['dport'])
                
        return tcp_packets

    def adjust_timestamps(self, packets, inter_packet_delay):
        # TODO: modify this s.t. after INIT & OPEN MSG (PEER UPs) we have larger inter-packet delay!

        packets_new = []
        reference_time = EDecimal(1672534800.000) # TODO: does this make sense?
        pkt_counter = 0

        for pkt in packets:
            pkt.time = reference_time + EDecimal(pkt_counter * inter_packet_delay)
            packets_new.append(pkt)
            pkt_counter += 1
        
        return packets_new

    def prep_for_repro(self, inter_packet_delay=0.001):

        # Get some info for self.info struct
        self.bmp_session_info()

        # Reconstruct TCP segments s.t. MTU~=1500
        packets = self.tcp_build_wrapper()

        # Adjust timestamps
        packets = self.adjust_timestamps(packets, inter_packet_delay)

        # temp only produce bgp messages as is to check if correct...
        logging.info(f"Size of processed BMP packets: {len(packets)}") 
        return [self.info, packets]
