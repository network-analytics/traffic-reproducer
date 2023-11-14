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
from pcap_utils.filter import filter_generator, bgp_msg_filter_generator
from pcap_utils.bmp_scapy.bgp import *
from pcap_utils.bmp_scapy.bmp import *

class BMPProcessing:

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
        packets = self.__extract_bmp_packets(pcap_file)
        packets = self.__bmp_sessions_cleanup(packets)
        packets = self.__bgp_defragment(packets)
        self.packets = packets