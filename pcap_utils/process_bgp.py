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
from scapy.contrib.bgp import *

import scapy.contrib.bgp
scapy.contrib.bgp.bgp_module_conf.use_2_bytes_asn = False

# Internal Libraries
from pcap_utils.process_proto import ProtoProcessing
from pcap_utils.scapy_helpers import get_layers, tcp_build, tcp_fragment
from pcap_utils.filter import filter_generator, bgp_msg_filter_generator

# Class for storing BGP packets belonging to a TCP session
class BGPSession:
    def __init__(self, ip_ver, ip_src, ip_dst):
        self.ip_ver = ip_ver
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.bgp_packets = []

class BGPProcessing(ProtoProcessing):
    def __init__(self, proto, pcap_file, selectors):
        ProtoProcessing.__init__(self, proto, pcap_file, selectors)

        #   self.info() template:
        #
        #   "ip_src": { ...
        #         "bgp_version": 
        #         "bgp_id":
        #         "as_number": 
        #         "capabilities": []
        #         "updates_counter": 
        #         "notif_counter":
        #         "keepalive_counter":
        #         "route_refresh_counter": 
        #                        ... }

        # List of BGPSession() instances
        self.bgp_sessions = [] 

        # Extract and cleanup BGP sessions from self.packets
        self.__bgp_sessions_cleanup()
        self.__bgp_sessions_defragment()

        # Some more filtering on BGP layers
        self.__bgp_apply_additional_filters()

    def __bgp_sessions_cleanup(self):
        # Select clean BGP sessions only
        #  --> discard all messages before BGP OPEN is received
        #  --> discard incomplete sessions (i.e. without any OPEN)
        #  --> discard too small packets

        packets_new = []
        tcp_sessions = self.packets.sessions()
        
        for session_id, plist in tcp_sessions.items():
            keep_session = False
            
            for packet in plist:
                bgp_packet = packet[TCP].payload

                # Check if we have an OPEN message
                if len(bgp_packet) >= 28 and raw(bgp_packet)[18] == 1: 
                    keep_session = True
                    packets_new.append(packet)
                else:
                    # Keep only packets after OPEN received
                    if keep_session and len(bgp_packet) >= 6: 
                        packets_new.append(packet)

        self.packets = PacketList(packets_new)

    def __bgp_sessions_defragment(self):
        # BGP messages defragment

        tcp_sessions = self.packets.sessions()
        tcp_port = self.selectors['tcp']['dport']
        
        # Process all BGP sessions
        for session_id, plist in tcp_sessions.items():

            logging.debug(f"Defragmenting BGP from TCP session [ID = {session_id}]")
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

            raw_bgp_packets = []
            bgp_session = BGPSession(ip_ver, ip_src, ip_dst)            

            # Defragmenting BGP session
            reassembled_raw = None
            for packet in plist:

                #packet.show()
                
                if packet[TCP].payload.name == "Raw":
                    if not reassembled_raw:
                        reassembled_raw = raw_bgp_packets.pop() + raw(packet[TCP].payload)
                    else:
                        reassembled_raw += raw(packet[TCP].payload)

                else:
                    if reassembled_raw:
                        raw_bgp_packets.append(reassembled_raw)
                        reassembled_raw = None
                        
                    raw_bgp_packets.append(raw(packet[TCP].payload))

            # Append last packet if we have remaining raw payload
            if reassembled_raw:
                raw_bgp_packets.append(reassembled_raw)

            # Split up and get single BGP messages
            for raw_bgp_packet in raw_bgp_packets:
                bgp_hdr = BGP(raw_bgp_packet[:19])

                while bgp_hdr.getlayer(BGPHeader):
                    length = bgp_hdr[BGPHeader].len
                    bgp_session.bgp_packets.append(BGP(raw_bgp_packet[:length]))

                    # Load next header
                    raw_bgp_packet = raw_bgp_packet[length:]
                    bgp_hdr = BGP(raw_bgp_packet[:19])

                # Handle BPGKeepAlive case (has no scapy BGPHeader)
                while bgp_hdr.getlayer(BGPKeepAlive):
                    length = bgp_hdr[BGPKeepAlive].len
                    bgp_session.bgp_packets.append(BGP(raw_bgp_packet[:length]))

                    # Load next header
                    raw_bgp_packet = raw_bgp_packet[length:]
                    bgp_hdr = BGP(raw_bgp_packet[:19])
                    
            self.bgp_sessions.append(bgp_session)

    def __bgp_apply_additional_filters(self):
        # Apply more advanced filters if provided in proto selectors, 
        # i.e. BGP msg type

        # Generate filter from selectors
        proto_filter = bgp_msg_filter_generator(self.selectors)

        for i in range(0, len(self.bgp_sessions)):

            bgp_packets_new = []
            for bgp_packet in self.bgp_sessions[i].bgp_packets:

                #get_layers(bgp_packet, do_print=True, layer_limit=5)
                
                if proto_filter(bgp_packet):
                    bgp_packets_new.append(bgp_packet)
            
            self.bgp_sessions[i].bgp_packets = bgp_packets_new


    def register_bgp_open(self, ip_src, bgp_packet):

        self.info[str(ip_src)]['bgp_version'] = bgp_packet[BGPOpen].version
        self.info[str(ip_src)]['bgp_id'] = bgp_packet[BGPOpen].bgp_id
        self.info[str(ip_src)]['as_number'] = bgp_packet[BGPOpen].my_as

        # Process some of the Capabilities (BGP Option Params)
        self.info[str(ip_src)]['capabilities'] = [] 

        if bgp_packet.getlayer(BGPCapFourBytesASN):
            self.info[str(ip_src)]['capabilities'].append("BGPCapFourBytesASN")

        if bgp_packet.getlayer(BGPCapGracefulRestart):
            self.info[str(ip_src)]['capabilities'].append("BGPCapGracefulRestart")  

        if bgp_packet.getlayer(BGPCapORF):
            self.info[str(ip_src)]['capabilities'].append("BGPCapORF")

        i = 1
        while bgp_packet.getlayer(BGPCapMultiprotocol, i):

            afi = bgp_packet.getlayer(BGPCapMultiprotocol, i).afi
            safi = bgp_packet.getlayer(BGPCapMultiprotocol, i).safi
            self.info[str(ip_src)]['capabilities'].append("BGPCapMultiprotocol: AFI_" + str(afi) + " + SAFI_" + str(safi))
            i += 1

        i = 1
        while bgp_packet.getlayer(BGPCapGeneric, i):

            cap_code = bgp_packet.getlayer(BGPCapGeneric, i).code

            # TODO: implement class for this capability and contribute it to scapy
            if cap_code == 5: self.info[str(ip_src)]['capabilities'].append("BGPCapExtendedNHEnconding") 
            else: self.info[str(ip_src)]['capabilities'].append("BGPCapGeneric_" + str(cap_code))
            i += 1

        self.info[str(ip_src)]['updates_counter'] = 0
        self.info[str(ip_src)]['keepalives_counter'] = 0

    def register_bgp_updates(self, ip_src, bgp_packet):
      i = 1
      while bgp_packet.getlayer(BGPUpdate, i):
  
          # Add/modify msg type counters
          self.info[str(ip_src)]['updates_counter'] += 1
          i += 1

    def bgp_session_info(self):
        for bgp_session in self.bgp_sessions:
            if str(bgp_session.ip_src) not in self.info.keys():
                self.info[str(bgp_session.ip_src)] = {}
            
            for bgp_packet in bgp_session.bgp_packets:

                # DEBUG PRINT:
                #get_layers(bgp_packet, do_print=True, layer_limit=5)

                # BGP Open
                if bgp_packet.haslayer(BGPOpen):
                    self.register_bgp_open(bgp_session.ip_src, bgp_packet)

                # BGP Updates
                if bgp_packet.haslayer(BGPUpdate):
                    self.register_bgp_updates(bgp_session.ip_src, bgp_packet)

                # BGP Keepalives
                if bgp_packet.haslayer(BGPKeepAlive):
                    self.info[str(bgp_session.ip_src)]['keepalives_counter'] += 1


    def tcp_build_wrapper_BGP(self):
        # - groups messages by msg_type
        # - calls tcp_build helper to construct TCP segments s.t. MTU ~= 1500
        # - calls tcp_fragment to make sure MTU < 1500
        tcp_packets = []
        
        for bgp_session in self.bgp_sessions:
            payloads = []
            prev_msg_type = 999

            tcp_seq_nr = 1
            for bgp_packet in bgp_session.bgp_packets:

                # Handle BPGKeepAlive case (has no scapy BGPHeader)
                msg_type = bgp_packet[BGPKeepAlive].type if bgp_packet.getlayer(BGPKeepAlive) else\
                           bgp_packet[BGPHeader].type
                
                if (msg_type != prev_msg_type and payloads):
                    tmp_tcp_packets,tcp_seq_nr = tcp_build(payloads, bgp_session.ip_ver,
                                                          bgp_session.ip_src, bgp_session.ip_dst,
                                                          self.selectors['tcp']['dport'],
                                                          tcp_seq_nr)
                    tcp_packets += tmp_tcp_packets
                    payloads = [bgp_packet] # initialize new payloads list
                    prev_msg_type = msg_type
                else:
                    payloads.append(bgp_packet)

            if (payloads): 
                tmp_tcp_packets,tcp_seq_nr = tcp_build(payloads, bgp_session.ip_ver,
                                                      bgp_session.ip_src, bgp_session.ip_dst,
                                                      self.selectors['tcp']['dport'],
                                                      tcp_seq_nr)
                tcp_packets += tmp_tcp_packets

        tcp_packets = tcp_fragment(PacketList(tcp_packets), self.selectors['tcp']['dport'])
                
        self.packets = PacketList(tcp_packets)


    def adjust_timestamps_BGP(self, initial_delay, inter_packet_delay):
        packets_new = []
        reference_time = EDecimal(initial_delay + 1672534800.000)
        pkt_counter = 0

        for pkt in self.packets:
            pkt.time = reference_time + EDecimal(pkt_counter * inter_packet_delay)
            packets_new.append(pkt)
            pkt_counter += 1

            # Check if we have an OPEN msg at the beginning of a tcp session
            # --> then add 1s delay after it
            if (pkt[TCP].seq == 1 and raw(pkt[TCP].payload)[18]) == 1:
                reference_time += EDecimal(1)

        self.packets = PacketList(packets_new)


    def prep_for_repro(self, initial_delay=5, inter_packet_delay=0.001):

        # Get some info for self.info struct
        self.bgp_session_info()

        # Reconstruct TCP segments s.t. MTU~=1500 (<1500)
        self.tcp_build_wrapper_BGP()

        # Adjust timestamps
        self.adjust_timestamps_BGP(initial_delay, inter_packet_delay)

        # temp only produce bgp messages as is to check if correct...
        logging.info(f"Size of processed BGP packets: {len(self.packets)}") 
        return [self.info, self.packets]
