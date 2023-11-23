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
from pcap_utils.scapy_helpers import get_layers, tcp_fragment
from pcap_utils.filter import filter_generator
from pcap_utils.bmp_scapy.bmp import *

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
        self.bmp_selectors = bmp_selectors

        # Initial BMP processing
        packets = self.__extract_bmp_packets(pcap_file)
        packets = self.__bmp_sessions_cleanup(packets)
        packets = self.__bmp_defragment(packets)
        self.packets = packets

    def __extract_bmp_packets(self, pcap_file):
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
        #  --> discard too small packets (i.e. packets smaller than 19bytes)

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
                    # TODO: find out better way to remove TCP packets
                    #       not related to bmp -> proper tcp reassembly
                    if keep_session and len(bmp_packet) >= 6: 
                        packets_new.append(packet)

        return PacketList(packets_new)

#    def __bmp_apply_additional_filters(self, bmp_packets):
#        # Apply more advanced filters if provided in proto selectors, 
#        # i.e. BMP msg type
#
#        bmp_packets_new = []
#
#        # Generate filter from selectors
#        proto_filter = bmp_msg_filter_generator(self.bmp_selectors)
#
#        for packet in bmp_packets:
#            if proto_filter(packet):
#                bmp_packets_new.append(packet)
#
#        return PacketList(bmp_packets_new)

    def __bmp_defragment(self, packets):
        # Quick & dirty BMP message defragment (not thoroughly tested)

        packets_new = []
        tcp_sessions = packets.sessions()
        tcp_port = self.bmp_selectors['tcp']['dport']
        
        # Process all BMP sessions
        for session_id, plist in tcp_sessions.items():

            bmp_packets = []
            logging.debug(f"Reassembling BMP from TCP session [ID = {session_id}]")
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

            # TODO: recreate TCP only at the end in separate function
            # TODO: first separate all bmp packets in per packet (after the tcp payload has been reassembled...)
            # TODO: then we can do the same for BGP if there's time

            reassembled_raw = None
            for packet in plist:

                #packet.show()
                
                if packet[TCP].payload.name == "Raw":
                    if not reassembled_raw:
                        reassembled_raw = raw(bmp_packets.pop()) + raw(packet[TCP].payload)
                    else:
                        reassembled_raw += raw(packet[TCP].payload)

                else:
                    if reassembled_raw:
                        bmp_packets.append(BMP(reassembled_raw))
                        reassembled_raw = None
                        
                    bmp_packets.append(packet[TCP].payload)

            # Append last packet if we have remaining raw payload
            if reassembled_raw:
                bmp_packets.append(BMP(reassembled_raw))

            # Apply additional filters # TODO: implement the filters to include/exclude BMP msg type
            #bmp_packets = self.__bmp_apply_additional_filters(bmp_packets)

            # Reconstruct packets (regenerate Ether/IP/TCP headers)
            next_tcp_seq_nr = 1
            for bmp_packet in bmp_packets:

                if(next_tcp_seq_nr == 1): bmp_packet.show()
                print(bmp_packet.summary())
                
                tcp_payload_size = len(raw(bmp_packet))
                flg = 0x02 if next_tcp_seq_nr == 1 else 0x18
                if IP in first_pkt:
                    reassembled_ether = Ether() /\
                                        IP(src=ip_src, dst=ip_dst) /\
                                        TCP(seq=next_tcp_seq_nr, ack=next_tcp_seq_nr-1, flags=flg, dport=tcp_port) /\
                                        Raw(load=raw(bmp_packet))
                    
                elif IPv6 in  first_pkt:
                    reassembled_ether = Ether() /\
                                        IPv6(src=ip_src, dst=ip_dst) /\
                                        TCP(seq=next_tcp_seq_nr, ack=next_tcp_seq_nr-1, flags=flg, dport=tcp_port) /\
                                        Raw(load=raw(bmp_packet))
                
                next_tcp_seq_nr += tcp_payload_size
                packets_new.append(reassembled_ether)

        logging.debug(f"Size of defragmented BMP packets: {len(packets_new)}")

        return PacketList(packets_new)

    def prep_for_repro(self, inter_packet_delay=0.001, random_seed=0):

        # Get some info for self.info struct
        #self.bmp_session_info()

        # Reconstruct TCP segments s.t. MTU<1500
        #self.packets = tcp_fragment(self.packets, self.bmp_selectors['tcp']['dport'])

        # Adjust timestamps
        #self.adjust_timestamps(inter_packet_delay)

        logging.info(f"Size of processed BMP packets: {len(self.packets)}") 
        return [self.info, self.packets]
