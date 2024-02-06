#
# Copyright(c) 2023 Swisscom (Schweiz) AG
# Authors: Marco Tollini, Leonardo Rodoni
# Distributed under the MIT License (http://opensource.org/licenses/MIT)
#

# TODOs:
# - write_pcap(self, output_pcap) function (s.t. this class can be used standalone...)
# - pseudo anonymize support

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
from pcap_utils.process_proto import ProtoProcessing
from pcap_utils.scapy_helpers import get_layers, tcp_fragment, tcp_build, adjust_timestamps
from pcap_utils.filter import filter_generator, bmp_msg_filter_generator
from pcap_utils.bmp_scapy.bmp import *

# Class for storing BMP packets belonging to a TCP session
class BMPSession:
    def __init__(self, ip_ver, ip_src, ip_dst):
        self.ip_ver = ip_ver
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.bmp_packets = []

class BMPProcessing(ProtoProcessing):
    def __init__(self, proto, pcap_file, selectors):
        ProtoProcessing.__init__(self, proto, pcap_file, selectors)

        #   self.info() template:
        #
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

        # List of BMPSession() instances
        self.bmp_sessions = []

        # Extract and cleanup BMP sessions from self.packets
        self.__bmp_sessions_cleanup()
        self.__bmp_sessions_defragment() 
        
        # Some more filtering on BMP layers
        self.__bmp_apply_additional_filters()

    def __bmp_sessions_cleanup(self):
        # Select clean BMP sessions only
        #  --> discard all messages before BMP INIT is received
        #  --> discard incomplete sessions (i.e. without any INIT)
        #  --> discard too small packets

        packets_new = []
        tcp_sessions = self.packets.sessions()
        
        for session_id, plist in tcp_sessions.items():
            keep_session = False
            
            for packet in plist:
                bmp_packet = packet[TCP].payload

                # Check if we have an INIT message
                if len(bmp_packet) >= 6 and raw(bmp_packet)[5] == 4: 
                    keep_session = True
                    packets_new.append(packet)
                else:
                    # Keep only packets after INIT received
                    if keep_session and len(bmp_packet) >= 6: 
                        packets_new.append(packet)

        self.packets = PacketList(packets_new)

    def __bmp_sessions_defragment(self):
        # BMP messages defragment

        tcp_sessions = self.packets.sessions()
        tcp_port = self.selectors['tcp']['dport']
        
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

            raw_bmp_packets = []
            bmp_session = BMPSession(ip_ver, ip_src, ip_dst)            

            # Defragmenting BMP session
            reassembled_raw = None
            for packet in plist:

                #packet.show()
                
                if packet[TCP].payload.name == "Raw":
                    if not reassembled_raw:
                        reassembled_raw = raw_bmp_packets.pop() + raw(packet[TCP].payload)
                    else:
                        reassembled_raw += raw(packet[TCP].payload)

                else:
                    if reassembled_raw:
                        raw_bmp_packets.append(reassembled_raw)
                        reassembled_raw = None
                        
                    raw_bmp_packets.append(raw(packet[TCP].payload))

            # Append last packet if we have remaining raw payload
            if reassembled_raw:
                raw_bmp_packets.append(reassembled_raw)

            # Split up and get single BMP messages
            for raw_bmp_packet in raw_bmp_packets:
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
        proto_filter = bmp_msg_filter_generator(self.selectors)

        for i in range(len(self.bmp_sessions)):

            bmp_packets_new = []
            for bmp_packet in self.bmp_sessions[i].bmp_packets:
                if proto_filter(bmp_packet):
                    bmp_packets_new.append(bmp_packet)
            
            self.bmp_sessions[i].bmp_packets = bmp_packets_new


    def register_bgp_open(self, ip_src, peer_bgp_id_str, bgp_packet):

        self.info[str(ip_src)]['BGP_Peers'][peer_bgp_id_str]['bgp_version'] = bgp_packet[BGPOpen].version

        # TODO: check capabilities if necessary

        self.info[str(ip_src)]['BGP_Peers'][peer_bgp_id_str]['route_monitoring_counter'] = 0
        self.info[str(ip_src)]['BGP_Peers'][peer_bgp_id_str]['stats_counter'] = 0

    def register_bmp_peerup(self, ip_src, bmp_packet):

        peer_bgp_id = bmp_packet[PerPeerHeader].peer_bgp_id

        #bmp_packet.show()
        #get_layers(bmp_packet, do_print=True, layer_limit=10)

        if str(peer_bgp_id) not in self.info[str(ip_src)]['BGP_Peers'].keys():
            
            # TODO: investigate better (corner case for FRR where we don't receive BGP_ID but 0.0.0.0 for local router BGP process in OPEN)
            if str(peer_bgp_id) == '0.0.0.0': 
                self.info[str(ip_src)]['BGP_Peers'][str(ip_src)] = {"as_number": bmp_packet[PerPeerHeader].peer_asn}
                self.register_bgp_open(ip_src, str(ip_src), bmp_packet)

            self.info[str(ip_src)]['BGP_Peers'][str(peer_bgp_id)] = {"as_number": bmp_packet[PerPeerHeader].peer_asn}
            self.register_bgp_open(ip_src, str(peer_bgp_id), bmp_packet)

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

    def tcp_build_wrapper_BMP(self, tcp_payload_size=1424):
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
                                                          self.selectors['tcp']['dport'],
                                                          tcp_seq_nr,
                                                          tcp_payload_size)
                    tcp_packets += tmp_tcp_packets
                    payloads = [bmp_packet]
                    msg_type = bmp_packet[BMPHeader].type
                else:
                    payloads.append(bmp_packet)

            if (payloads): 
                tmp_tcp_packets,tcp_seq_nr = tcp_build(payloads, bmp_session.ip_ver,
                                                      bmp_session.ip_src, bmp_session.ip_dst,
                                                      self.selectors['tcp']['dport'],
                                                      tcp_seq_nr,
                                                      tcp_payload_size)
                tcp_packets += tmp_tcp_packets

        tcp_packets = tcp_fragment(PacketList(tcp_packets), self.selectors['tcp']['dport'])
                
        self.packets = PacketList(tcp_packets)

    def adjust_timestamps_BMP(self, initial_delay, inter_packet_delay):
        packets_new = []
        reference_time = EDecimal(initial_delay + 1672534800.000)
        pkt_counter = 0

        for pkt in self.packets:
            pkt.time = reference_time + EDecimal(pkt_counter * inter_packet_delay)
            packets_new.append(pkt)
            pkt_counter += 1

            # Check if we have a peer-up message, and add some delay before
            if (raw(pkt[TCP].payload)[5] == 3):
                self.packets[pkt_counter-1].time += EDecimal(2)
                reference_time += EDecimal(2)

            # Check if we have a peer-down message, and add some delay before
            if (raw(pkt[TCP].payload)[5] == 2):
                self.packets[pkt_counter-1].time += EDecimal(5)
                reference_time += EDecimal(5)

        self.packets = PacketList(packets_new)

    def prep_for_repro(self, initial_delay=5, inter_packet_delay=0.001, tcp_payload_size=1424):

        # Get some info for self.info struct
        self.bmp_session_info()

        # Reconstruct TCP segments s.t. MTU~=1500 (<1500)
        self.tcp_build_wrapper_BMP(tcp_payload_size)

        # Adjust timestamps
        #self.packets = adjust_timestamps(self.packets, initial_delay, inter_packet_delay)
        self.adjust_timestamps_BMP(initial_delay, inter_packet_delay)


        # temp only produce bgp messages as is to check if correct...
        logging.info(f"Size of processed BMP packets: {len(self.packets)}") 
        return [self.info, self.packets]
