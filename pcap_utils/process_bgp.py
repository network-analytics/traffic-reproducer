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
from scapy.all import IP, IPv6, raw, rdpcap
from scapy.contrib.bgp import *

# Internal Libraries
from pcap_utils.filter import filter_generator

class BGPProcessing:
    def __init__(self, pcap_file, bgp_selectors, inter_packet_delay, random_seed):

        #   "ip_src": {
        #       "BGP Version"
        #           "BGP ID": { ...
        #               "AS number": 
        #               "capabilities": []
        #               "updates_counter": 
        #               "withdraws_counter":
        #                            ... }
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

    # Inspect packet by packet while:
    #   - removing updates/withdrawals with no previously receive OPEN message
    #   - for we don't support TCP reassembly: just keep all packets...
    #     --> for the anonymization feature this is required otherwise payload cannot be dissected...
    #     --> we expect full complete bgp sessions to be in the pcap
    #     --> should not be too hard to implement, as scapy already gives you Raw data
    #   - adding some info to traffic-info.json
    def inspect_and_cleanup(self, bgp_packets):
        packets_new = []

        for packet in bgp_packets:

            # Add ip_src to self.info dict
            if IP in packet:
                ip_src = packet[IP].src
            elif IPv6 in packet:
                ip_src = packet[IPv6].src

            if str(ip_src) not in self.info.keys():
                self.info[str(ip_src)] = {}

            # Get BGP packet
            bgp_payload = packet[TCP].payload

            # Decode BGP
            #bgp_packet = 

            #packet.show()
            # TMP Get BGP Layers (helper for development)
            #print("   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ")
            #layers = self.__get_layers(bgp_payload, True)

            #print("last incomplete layers", layers[-2])
            #print(" --> bytes = ", len(layers[-2]))

            packets_new.append(packet)
        
        return packets_new

    # Quick & dirty reassembly of BGP packets
    # Have a look at pynids or pyshark to reassemble the stream!
    def fast_tcp_reassembly(self, packets):
        packets_new = []

        for packet in packets:

            # Get BGP packet
            bgp_packet = packet[TCP].payload

# NOT WORKING SO FAR....
#            i = 1
#            while bgp_packet.getlayer("BGPHeader", i):
#
#                bgp_header = bgp_packet.getlayer("BGPHeader", i)
#                if len(bgp_header) == bgp_header.len:
#                    print(len(bgp_header))
#                    print(bgp_header.len)
#                    print("ok")
#                
#                i = i + 1

            packets_new.append(packet)
        
        return packets_new


    # Extract BGP packets with selectors
    def extract_bgp_packets(self, packets):
        packets_new = []

        # Generate filter from selectors
        logging.debug(f"bgp_selectors: {self.bgp_selectors}")
        proto_filter = filter_generator(self.bgp_selectors)

        for packet in packets:
            
            if proto_filter(packet):
                packets_new.append(packet)

        return packets_new

    def start(self):

        # Load pcap in memory
        packets = rdpcap(self.pcap_file)
        logging.info(f"Size of packets: {len(packets)}") 

        # Extract IPFIX/NetFlow packets and defragment
        packets = self.extract_bgp_packets(packets)
        logging.debug(f"Size of BGP packets: {len(packets)}")

        # BGP defragment/fix segment numbers etc.. (investigate howTO)
        # --> reassembly bgp payloads s.t. updates are not cut in half between packets...
        #packets = self.fast_tcp_reassembly(packets)

        # Start processing
        packets = self.inspect_and_cleanup(packets)

        logging.info(f"Size of BGP packets processed: {len(packets)}") 

        return [self.info, packets]
