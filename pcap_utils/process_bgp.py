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
from scapy.all import Ether, IP, IPv6, Raw, raw, rdpcap, PacketList, EDecimal
from scapy.contrib.bgp import *

#BGPConf.use_2_bytes_asn = False

# Internal Libraries
from pcap_utils.scapy_helpers import get_layers
from pcap_utils.filter import filter_generator, bgp_msg_filter_generator

class BGPProcessing:

    def __init__(self, pcap_file, bgp_selectors):

        #   "ip_src": { ...
        #         "bgp_version"
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
                    if keep_session: packets_new.append(packet)

        return PacketList(packets_new)

    def __bgp_apply_additional_filters(self, bgp_packets):
        # Apply more advanced filters if provided in proto selectors, 
        # i.e. BGP msg type

        bgp_packets_new = []

        # Generate filter from selectors
        proto_filter = bgp_msg_filter_generator(self.bgp_selectors)

        for packet in bgp_packets:
            if proto_filter(packet):
                bgp_packets_new.append(packet)

        return PacketList(bgp_packets_new)

    def __bgp_defragment(self, packets):
        # Quick & dirty BGP message defragment (TCP reassembly)
        #  --> no guarante of working in all scenarios!

        packets_new = []
        tcp_sessions = packets.sessions()
        
        # Process all BGP sessions
        for session_id, plist in tcp_sessions.items():

            bgp_packets = []
            logging.debug(f"Reassembling BGP from TCP session [ID = {session_id}]")
            #print(plist.summary())

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
                                        TCP(seq=next_tcp_seq_nr, ack=next_tcp_seq_nr-1, flags=flg, dport=179) /\
                                        Raw(load=raw(bgp_packet))
                    
                elif IPv6 in  first_pkt:
                    reassembled_ether = Ether() /\
                                        IPv6(src=ip_src, dst=ip_dst) /\
                                        TCP(seq=next_tcp_seq_nr, ack=next_tcp_seq_nr-1, flags=flg, dport=179) /\
                                        Raw(load=raw(bgp_packet))
                
                next_tcp_seq_nr += tcp_payload_size
                packets_new.append(reassembled_ether)

        logging.debug(f"Size of defragmented BGP packets: {len(packets_new)}")

        return PacketList(packets_new)

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

    def register_bgp_open(self, ip_src, bgp_packet):
        self.info[str(ip_src)]['bgp_version'] = bgp_packet[BGPOpen].version
        self.info[str(ip_src)]['bgp_id'] = bgp_packet[BGPOpen].bgp_id
        self.info[str(ip_src)]['as_number'] = bgp_packet[BGPOpen].my_as
        self.info[str(ip_src)]['capabilities'] = [] 
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
            #layers = get_layers(bgp_packet, True)

            # BGP Open
            if bgp_packet.haslayer(BGPOpen):
                self.register_bgp_open(ip_src, bgp_packet)

            # BGP Updates
            if bgp_packet.haslayer(BGPUpdate):
                self.register_bgp_updates(ip_src, bgp_packet)

            # BGP Withdrawals
            if bgp_packet.haslayer(BGPKeepAlive):
                self.info[str(ip_src)]['keepalives_counter'] += 1

    def prep_for_repro(self, inter_packet_delay=0.001, random_seed=0):

        # Anonymize data (TODO)
        # TODO: determine if this is needed or not
        #self.pseudo_anonymize()

        # Get some info for self.info struct
        self.bgp_session_info()

        # Reconstruct TCP segments with MTU<1500 (TODO)
        # TODO: determine if this is needed or not
        #       --> this we could define as general function
        #           in scapy_helpers if we need it
        #self.tcp_fragment()

        # Adjust timestamps
        self.adjust_timestamps(inter_packet_delay)

        logging.info(f"Size of processed BGP packets: {len(self.packets)}") 
        return [self.info, self.packets]
