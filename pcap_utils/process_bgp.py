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

# Internal Libraries
from pcap_utils.filter import filter_generator
from pcap_utils.bgp_filter import bgp_filter_generator

class BGPProcessing:
    def __init__(self, pcap_file, bgp_selectors, inter_packet_delay, random_seed):

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

        self.pcap_file = pcap_file
        self.bgp_selectors = bgp_selectors
        self.inter_packet_delay = inter_packet_delay
        self.random_seed = random_seed
    
    # Scapy Helpers
    def __get_layers(self, packet, do_print=False):
        layers = []
        counter = 0
        while True:
            layer = packet.getlayer(counter)
            if layer is None:
                break

            layers.append(layer)

            if do_print:
                print(layer)

            counter += 1
        
        if do_print:
            print("Number of layers: ", counter)

        return layers

    # TODO: modify this s.t. after OPEN MSG we have larger inter-packet delay!
    def adjust_timestamps(self, packets):

        packets_new = []

        reference_time = EDecimal(1672534800.000) # does this make sense?
        
        pkt_counter = 0
        for pkt in packets:
            pkt.time = reference_time + EDecimal(pkt_counter * self.inter_packet_delay)
            packets_new.append(pkt)
            pkt_counter += 1
        
        return PacketList(packets_new)

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

    def bgp_session_info(self, packets):
        for packet in packets:

            bgp_packet = packet[TCP].payload

            # TMP Get BGP Layers (helper for development)
            #print("   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ")
            #layers = self.__get_layers(bgp_packet, True)

            # Add ip_src to self.info dict
            if IP in packet:
                ip_src = packet[IP].src
            elif IPv6 in packet:
                ip_src = packet[IPv6].src

            if str(ip_src) not in self.info.keys():
                self.info[str(ip_src)] = {}

            # BGP Open
            if bgp_packet.haslayer(BGPOpen):
                self.register_bgp_open(ip_src, bgp_packet)

            # BGP Updates
            if bgp_packet.haslayer(BGPUpdate):
                self.register_bgp_updates(ip_src, bgp_packet)

            # BGP Withdraw
            if bgp_packet.haslayer(BGPKeepAlive):
                self.info[str(ip_src)]['keepalives_counter'] += 1


    # Apply more advanced filters if provided in proto selectors, such as:
    # - bgp:type
    def bgp_apply_additional_filters(self, packets):
        packets_new = []

        # Generate filter from selectors
        proto_filter = bgp_filter_generator(self.bgp_selectors)

        for packet in packets:
            if proto_filter(packet):
                packets_new.append(packet)

        return PacketList(packets_new)

    # Quick & dirty payload reassembly of BGP sessions
    #  --> no guarante of working in all scenarios!
    def tcp_reassembly(self, packets):
        
        packets_new = []
        tcp_sessions = packets.sessions()
        
        # Process BGP sessions
        for session_id, plist in tcp_sessions.items():

            logging.debug(f"Reassembling TCP session [ID = {session_id}]")
            #print(plist.summary())
        
            # Reassemble TCP session
            for packet in plist:

                # TMP Get BGP Layers (helper for development)
                #print("   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ")
                #layers = self.__get_layers(packet, True)

                # Append payload to previous packet
                if packet[TCP].payload.name == "Raw":

                    print("PAYLOAD IS RAW --> appending to previous")

                    # Append the Raw payload to the previous packet
                    previous_raw = raw(packets_new[-1])
                    reassembled_raw = previous_raw + raw(packet[TCP].payload)
                    reassembled = Ether(reassembled_raw)

                    # Adjust TCP header params
                    reassembled[TCP].chksum = None
                    if IP in packet:
                        reassembled[IP].len += (packet[IP].len - 4*packet[IP].ihl - 4*packet[TCP].dataofs)
                        reassembled[IP].chksum = None
                    elif IPv6 in packet:
                        reassembled[IPv6].plen += (packet[IPv6].plen - 4*packet[TCP].dataofs)

                    packets_new[-1] = reassembled

                else:
                    packets_new.append(packet)
                                    
        return PacketList(packets_new)

    # BGP session cleanup
    # - discard all messages before OPEN is received
    # - discard incomplete sessions (i.e. without any OPEN)
    def bgp_session_cleanup(self, packets):
        
        packets_new = []
        tcp_sessions = packets.sessions()
        
        # Process BGP sessions
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
        

    # Extract BGP packets with selectors
    def extract_bgp_packets(self, packets):
        packets_new = []

        # Generate filter from selectors
        logging.debug(f"bgp_selectors: {self.bgp_selectors}")
        proto_filter = filter_generator(self.bgp_selectors)

        for packet in packets:
            if proto_filter(packet):
                packets_new.append(packet)

        return PacketList(packets_new)

    def start(self):

        # Load pcap in memory
        packets = rdpcap(self.pcap_file)
        logging.info(f"Size of packets: {len(packets)}") 

        # Extract IPFIX/NetFlow packets
        packets = self.extract_bgp_packets(packets)
        logging.debug(f"Size of BGP packets: {len(packets)}")

        # BGP session cleanup
        packets = self.bgp_session_cleanup(packets)

        # TCP reassembly
        # TODO: migliorare che ha dei problemi...
        # --> idea, magari basta aggiungere il filtro per ffffff nel filter (provare...!)
        #packets = self.tcp_reassembly(packets)

        # Filter on additional parameters if necessary
        #packets = self.bgp_apply_additional_filters(packets)

        # Anonymize

        # Adjust timestamps
        packets = self.adjust_timestamps(packets)

        # Get some info for self.info struct
        # KEEP IN MIND: counter accounting is broken if reassembly disabled...
        self.bgp_session_info(packets)

        logging.info(f"Size of BGP packets processed: {len(packets)}") 
        return [self.info, packets]
