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
from scapy.contrib.bgp import *

import scapy.contrib.bgp
scapy.contrib.bgp.bgp_module_conf.use_2_bytes_asn = False

# Internal Libraries
from pcap_utils.scapy_helpers import get_layers, tcp_fragment
from pcap_utils.filter import filter_generator, bgp_msg_filter_generator

class BGPProcessing:

    def __init__(self, pcap_file, bgp_selectors):

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
        self.info = {}
        self.bgp_selectors = bgp_selectors

        # Initial BGP processing
        packets = self.__extract_bgp_packets(pcap_file)
        packets = self.__bgp_sessions_cleanup(packets)
        packets = self.__bgp_defragment(packets)
        self.packets = packets

    def __extract_bgp_packets(self, pcap_file):
        # Extract BGP packets with filter selectors

        packets_new = []

        # Load pcap in memory
        packets = rdpcap(pcap_file)
        logging.info(f"Size of packets: {len(packets)}") 
        
        # Generate filter from selectors
        logging.debug(f"bgp_selectors: {self.bgp_selectors}")
        proto_filter = filter_generator(self.bgp_selectors)

        for packet in packets:
            if proto_filter(packet):
                packets_new.append(packet)

        logging.debug(f"Size of filtered packets [BGP selector]: {len(packets_new)}")

        return PacketList(packets_new)

    def __bgp_sessions_cleanup(self, packets):
        # Select clean BGP sessions only
        #  --> discard all messages before OPEN is received
        #  --> discard incomplete sessions (i.e. without any OPEN)
        #  --> discard too small packets (i.e. packets smaller than 19bytes)

        packets_new = []
        tcp_sessions = packets.sessions()
        
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
                    # TODO: find out better way to remove TCP packets
                    #       not related to bgp (as tcp payload to reassemble
                    #       for bgp packet could be < 18 ? --> not sure)
                    if keep_session and len(bgp_packet) > 18: 
                        packets_new.append(packet)

        return PacketList(packets_new)

    def __bgp_apply_additional_filters(self, bgp_packets):
        # Apply more advanced filters if provided in proto selectors, 
        # i.e. BGP msg type
        # TODO: this only applies at the first header (i.e. we assume messages of different type are not fragmented
        #       by the tcp implementation) -> I don't know whether this is always true...

        bgp_packets_new = []

        # Generate filter from selectors
        proto_filter = bgp_msg_filter_generator(self.bgp_selectors)

        for packet in bgp_packets:
            if proto_filter(packet):
                bgp_packets_new.append(packet)

        return PacketList(bgp_packets_new)

    def __bgp_defragment(self, packets):
        # Quick & dirty BGP message defragment (not thoroughly tested)
        # TODO (if we have time): we need to check size of all BGP messages vs.
        #                         the respective payload to see if messages are 
        #                         complete or we should discard them...

        packets_new = []
        tcp_sessions = packets.sessions()
        tcp_port = self.bgp_selectors['tcp']['dport']
        
        # Process all BGP sessions
        for session_id, plist in tcp_sessions.items():

            bgp_packets = []
            logging.debug(f"Reassembling BGP from TCP session [ID = {session_id}]")
            print(plist.summary())

            # Get IP addresses to later reconstruct packet headers
            first_pkt = plist[0]
            if IP in first_pkt:
                ip_src = first_pkt[IP].src
                ip_dst = first_pkt[IP].dst
            elif IPv6 in  first_pkt:
                ip_src = first_pkt[IPv6].src
                ip_dst = first_pkt[IPv6].dst

            # Reassemble TCP session
            reassembled_raw = None
            for packet in plist:
                
                if packet[TCP].payload.name == "Raw":
                    if not reassembled_raw:
                        reassembled_raw = raw(bgp_packets.pop()) + raw(packet[TCP].payload)
                    else:
                        reassembled_raw += raw(packet[TCP].payload)

                else:
                    if reassembled_raw:
                        bgp_packets.append(BGP(reassembled_raw))
                        reassembled_raw = None
                        
                    bgp_packets.append(packet[TCP].payload)

            # Append last packet if we have remaining raw payload
            if reassembled_raw:
                bgp_packets.append(BGP(reassembled_raw))

            # Apply additional filters
            bgp_packets = self.__bgp_apply_additional_filters(bgp_packets)

            # Reconstruct packets (regenerate Ether/IP/TCP headers)
            next_tcp_seq_nr = 1
            for bgp_packet in bgp_packets:
                
                tcp_payload_size = len(raw(bgp_packet))
                flg = 0x02 if next_tcp_seq_nr == 1 else 0x18
                if IP in first_pkt:
                    reassembled_ether = Ether() /\
                                        IP(src=ip_src, dst=ip_dst) /\
                                        TCP(seq=next_tcp_seq_nr, ack=next_tcp_seq_nr-1, flags=flg, dport=tcp_port) /\
                                        Raw(load=raw(bgp_packet))
                    
                elif IPv6 in  first_pkt:
                    reassembled_ether = Ether() /\
                                        IPv6(src=ip_src, dst=ip_dst) /\
                                        TCP(seq=next_tcp_seq_nr, ack=next_tcp_seq_nr-1, flags=flg, dport=tcp_port) /\
                                        Raw(load=raw(bgp_packet))
                
                next_tcp_seq_nr += tcp_payload_size
                packets_new.append(reassembled_ether)

        logging.debug(f"Size of defragmented BGP packets: {len(packets_new)}")

        return PacketList(packets_new)

    def register_bgp_open(self, ip_src, bgp_packet):

        #get_layers(bgp_packet, True)

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
        for packet in self.packets:

            # Add ip_src to self.info dict
            if IP in packet:
                ip_src = packet[IP].src
            elif IPv6 in packet:
                ip_src = packet[IPv6].src

            if str(ip_src) not in self.info.keys():
                self.info[str(ip_src)] = {}

            bgp_packet = BGPHeader(raw(packet[TCP].payload))

            # BGP Open
            if bgp_packet.haslayer(BGPOpen):
                self.register_bgp_open(ip_src, bgp_packet)

            # BGP Updates
            if bgp_packet.haslayer(BGPUpdate):
                self.register_bgp_updates(ip_src, bgp_packet)

            # BGP Keepalives
            if bgp_packet.haslayer(BGPKeepAlive):
                self.info[str(ip_src)]['keepalives_counter'] += 1

    def adjust_timestamps(self, inter_packet_delay):
        # TODO: modify this s.t. after OPEN MSG we have larger inter-packet delay!

        packets_new = []
        reference_time = EDecimal(1672534800.000) # TODO: does this make sense?
        pkt_counter = 0

        for pkt in self.packets:
            pkt.time = reference_time + EDecimal(pkt_counter * inter_packet_delay)
            packets_new.append(pkt)
            pkt_counter += 1
        
        self.packets = packets_new

    # TODO: other functions to implements...
    # Export processed BGP packets in pcap file # TODO: do this s.t. can be used standalone
    #def write_pcap(self, output_pcap):

    def prep_for_repro(self, inter_packet_delay=0.001, random_seed=0):

        # Anonymize data (TODO)
        # TODO: determine if this is needed or not
        #self.pseudo_anonymize()

        # Get some info for self.info struct
        self.bgp_session_info()

        # Reconstruct TCP segments s.t. MTU<1500
        self.packets = tcp_fragment(self.packets, self.bgp_selectors['tcp']['dport'])

        # Adjust timestamps
        self.adjust_timestamps(inter_packet_delay)

        logging.info(f"Size of processed BGP packets: {len(self.packets)}") 
        return [self.info, self.packets]
