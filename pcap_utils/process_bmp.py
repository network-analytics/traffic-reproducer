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
from pcap_utils.filter import filter_generator
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
        #       "BGP_peers": [
        #           { "bgp_version":
        #             "bgp_id":
        #             "as_number": 
        #             "capabilities": []    -> TODO: get the open from the peer ip
        #             "updates_counter": 
        #             "notif_counter":
        #             "keepalive_counter":
        #             "route_refresh_counter": },
        #           { ... }, ... ]
        #                        ... }
        self.info = {}
        self.bmp_sessions = [] # list of BMPSession() instances

        self.bmp_selectors = bmp_selectors

        # Extract BMP packets by TCP session and populate self.bmp_sessions
        packets = self.__bmp_extract(pcap_file)
        packets = self.__bmp_sessions_cleanup(packets)
        self.__bmp_sessions_defragment(packets)   
        
        # Some more filtering on BMP layers
        #self.__bmp_apply_additional_filters()



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
            print(plist.summary())

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

            # Split up and get single BMP messages # TODO: optimize by only decoding the first 6 bytes before of the raw blob to check the length!!
            for bmp_packet in bmp_packets_temp:

                raw_bmp_packet = raw(bmp_packet)
                bmp_hdr = BMP(raw_bmp_packet[:6])

                while bmp_hdr.getlayer(BMPHeader):

                    #bmp_hdr.show()

                    length = bmp_hdr[BMPHeader].len
                    print("length=", length)
                    bmp_session.bmp_packets.append(BMP(raw_bmp_packet[:length]))

                    raw_bmp_packet = raw_bmp_packet[length:]
                    bmp_hdr = BMP(raw_bmp_packet[:6])
                    
            self.bmp_sessions.append(bmp_session)

    # TODO: modify s.t. this uses self.bmp_packets
    #def __bmp_apply_additional_filters(self):
        # Apply more advanced filters if provided in proto selectors, 
        # i.e. BMP msg type

        # Generate filter from selectors
        #proto_filter = bmp_msg_filter_generator(self.bmp_selectors)

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


    def prep_for_repro(self, inter_packet_delay=0.001, random_seed=0):

        # Get some info for self.info struct
        #self.bmp_session_info()

        # Reconstruct TCP segments s.t. MTU~=1500
        # --> TODO: we also have to call tcp_fragment() after if we want to make sure 
        #           that MTU<1500 --> should not be needed as I don't expect so long bmp msgs.
        # --> ideally messages should not be split up (no fragmentation)...
        packets = tcp_build(self.bmp_sessions[0].bmp_packets,
                            self.bmp_sessions[0].ip_ver,
                            self.bmp_sessions[0].ip_src,
                            self.bmp_sessions[0].ip_dst,
                            self.bmp_selectors['tcp']['dport'])

        # Adjust timestamps
        packets = self.adjust_timestamps(packets, inter_packet_delay)

        # temp only produce bgp messages as is to check if correct...
        logging.info(f"Size of processed BMP packets: {len(packets)}") 
        return [self.info, packets]
