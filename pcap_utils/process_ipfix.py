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
from scapy.all import IP, IPv6, UDP, raw, rdpcap, EDecimal
from scapy.layers.netflow import *
from scapy.layers.l2 import *
from scapy.contrib.mpls import *

# Internal Libraries
from pcap_utils.filter import filter_generator
from pcap_utils.scapy_helpers import get_layers, ether_replace

class IpfixProcessing:
    def __init__(self, pcap_file, ipfix_selectors):

        #   "ip_src": {
        #       "IPFIX version": {
        #           "Observation ID": {
        #               "Template ID ": { ...
        #                   "type": 
        #                   "flowset_id": 
        #                   "data_flowset_counter": 
        #                                 ... }
        self.info = {}

        self.pcap_file = pcap_file
        self.ipfix_selectors = ipfix_selectors

        self.packets = self.__extract_and_defrag_ipfix_packets(pcap_file)

    def __extract_and_defrag_ipfix_packets(self, pcap_file):
        # Extract IPFIX/NetFlow packets with filter selectors

        # Load pcap in memory
        packets = rdpcap(pcap_file)
        logging.info(f"Size of packets: {len(packets)}") 

        packets_new = []

        # Generate filter from selectors
        logging.debug(f"ipfix_selectors: {self.ipfix_selectors}")
        proto_filter = filter_generator(self.ipfix_selectors)

        for packet in packets:
            
            if proto_filter(packet):
                packets_new.append(packet)
        
        logging.debug(f"Size of filtered packets [IPFIX selector]: {len(packets_new)}")

        packets_new = netflowv9_defragment(packets_new)
        logging.debug(f"Size of defragmented ipfix packets: {len(packets_new)}")
        
        return packets_new

    # Add some info to self.info dict for v5 records
    def register_v5_info(self, ip_src, ipfix_packet):

        ipfix_version = "Version " + str(ipfix_packet.version)

        if ipfix_version not in self.info[ip_src].keys():
            self.info[ip_src][ipfix_version] = {}

        engineID = "EngineID " + str(ipfix_packet.engineID)
        if engineID not in self.info[ip_src][ipfix_version].keys():
            self.info[ip_src][ipfix_version][engineID] = {"data_packet_counter": 0}
        else:
            self.info[ip_src][ipfix_version][engineID]["data_packet_counter"] += 1

    # Check if data template is there already, otherwise register
    def register_data_template(self, ip_src, ipfix_packet):

        if ipfix_packet.haslayer(NetflowHeaderV9):
            SourceID = ipfix_packet.SourceID
        elif ipfix_packet.haslayer(NetflowHeaderV10):
            SourceID = ipfix_packet.ObservationDomainID

        i = 1
        while ipfix_packet.getlayer(NetflowFlowsetV9, i):
        
            # Dissect some fields
            flowSetID = ipfix_packet.getlayer(NetflowFlowsetV9, i).flowSetID
            templateID = ipfix_packet.getlayer(NetflowTemplateV9, i).templateID
            field_count = ipfix_packet.getlayer(NetflowTemplateV9, i).fieldCount
            length = ipfix_packet.getlayer(NetflowFlowsetV9, i).length

            # Gather data template fields summary
            templates = ipfix_packet.getlayer(NetflowFlowsetV9, i).templates

            # Add some information to self.info dict
            ipfix_version = "Version " + str(ipfix_packet.version)
            if ipfix_version not in self.info[ip_src].keys():
                self.info[ip_src][ipfix_version] = {}

            SourceID_str = "ObservationID " + str(SourceID)
            if SourceID_str not in self.info[ip_src][ipfix_version].keys():
                self.info[ip_src][ipfix_version][SourceID_str] = {}

            template = "Template " + str(templateID)
            if template not in self.info[ip_src][ipfix_version][SourceID_str].keys():
                self.info[ip_src][ipfix_version][SourceID_str][template] ={"type": "Data Template",
                                                                       "flowset_id": flowSetID, 
                                                                       "template_length": length,
                                                                       "template_field_count": field_count, 
                                                                       "data_flowset_counter": 0}

            i = i + 1

    # Check if option template [v9] is there already, otherwise register
    def register_option_templatev9(self, ip_src, ipfix_packet):

        SourceID = ipfix_packet.SourceID
        
        i = 1
        while ipfix_packet.getlayer(NetflowOptionsFlowsetV9, i):

            # Dissect some fields
            templateID = ipfix_packet.getlayer(NetflowOptionsFlowsetV9, i).templateID
            flowSetID = ipfix_packet.getlayer(NetflowOptionsFlowsetV9, i).flowSetID
            length = ipfix_packet.getlayer(NetflowOptionsFlowsetV9, i).length

            # Gather option template fields summary
            scopes = ipfix_packet.getlayer(NetflowOptionsFlowsetV9, i).scopes
            options = ipfix_packet.getlayer(NetflowOptionsFlowsetV9, i).options

            # Add some information to self.info dict
            ipfix_version = "Version " + str(ipfix_packet.version)
            if ipfix_version not in self.info[ip_src].keys():
                self.info[ip_src][ipfix_version] = {}

            SourceID_str = "ObservationID " + str(SourceID)
            if SourceID_str not in self.info[ip_src][ipfix_version].keys():
                self.info[ip_src][ipfix_version][SourceID_str] = {}
        
            template = "Template " + str(templateID)
            if template not in self.info[ip_src][ipfix_version][SourceID_str].keys():
                self.info[ip_src][ipfix_version][SourceID_str][template] ={"type": "Option Template", 
                                                                       "flowset_id": flowSetID, 
                                                                       "template_length": length, 
                                                                       "template_field_count": len(scopes) + len(options), 
                                                                       "template_scopes_count": len(scopes),
                                                                       "template_options_count": len(options),
                                                                       "data_flowset_counter": 0}

            # Detect if it is a sampling options, and if yes gather some info
            for option in options: # TODO check also scopes (maybe some of that is in a scope field)
                if option.optionFieldType in [34, 48, 305, 309]:
                    self.info[ip_src][ipfix_version][SourceID_str][template]['option_description'] = "sampling"

            i = i + 1

    # Check if option template [v10] is there already, otherwise register
    def register_option_templatev10(self, ip_src, ipfix_packet):

        SourceID = ipfix_packet.ObservationDomainID

        i = 1
        while ipfix_packet.getlayer(NetflowOptionsFlowset10, i):

            # Dissect some fields
            templateID = ipfix_packet.getlayer(NetflowOptionsFlowset10, i).templateID
            flowSetID = ipfix_packet.getlayer(NetflowOptionsFlowset10, i).flowSetID
            field_count = ipfix_packet.getlayer(NetflowOptionsFlowset10, i).field_count
            length = ipfix_packet.getlayer(NetflowOptionsFlowset10, i).length

            # Gather option template fields summary
            scopes = ipfix_packet.getlayer(NetflowOptionsFlowset10, i).scopes
            options = ipfix_packet.getlayer(NetflowOptionsFlowset10, i).options
        
            # Add some information to self.info dict
            ipfix_version = "Version " + str(ipfix_packet.version)
            if ipfix_version not in self.info[ip_src].keys():
                self.info[ip_src][ipfix_version] = {}

            SourceID_str = "ObservationID " + str(SourceID)
            if SourceID_str not in self.info[ip_src][ipfix_version].keys():
                self.info[ip_src][ipfix_version][SourceID_str] = {}
        
            template = "Template " + str(templateID)
            if template not in self.info[ip_src][ipfix_version][SourceID_str].keys():
                self.info[ip_src][ipfix_version][SourceID_str][template] ={"type": "Option Template", 
                                                                       "flowset_id": flowSetID, 
                                                                       "template_length": length, 
                                                                       "template_field_count": field_count, 
                                                                       "template_scopes_count": len(scopes),
                                                                       "template_options_count": len(options),
                                                                       "data_flowset_counter": 0}

            # Detect if it is a sampling options, and if yes gather some info
            for option in options: # TODO check also scopes (maybe some of that is in a scope field)
                if option.optionFieldType in [34, 48, 305, 309]:
                    self.info[ip_src][ipfix_version][SourceID_str][template]['option_description'] = "sampling"

            i = i + 1

    def template_for_data_packet_exists(self, ip_src, ipfix_packet):

        #ipfix_packet.show()

        if ipfix_packet.haslayer(NetflowHeaderV9):
            SourceID = ipfix_packet.SourceID
        elif ipfix_packet.haslayer(NetflowHeaderV10):
            SourceID = ipfix_packet.ObservationDomainID

        i = 1
        while ipfix_packet.getlayer(NetflowDataflowsetV9, i):

            # Get template ID for Flowset
            templateID = ipfix_packet.getlayer(NetflowDataflowsetV9, i).templateID
        
            ipfix_version = "Version " + str(ipfix_packet.version)
            if ipfix_version not in self.info[ip_src].keys():
                return False

            SourceID_str = "ObservationID " + str(SourceID)
            if SourceID_str not in self.info[ip_src][ipfix_version].keys():
                return False       

            template = "Template " + str(templateID)
            if template not in self.info[ip_src][ipfix_version][SourceID_str].keys():
                return False
  
            # Adjust counter
            self.info[ip_src][ipfix_version][SourceID_str][template]["data_flowset_counter"] += 1

            # Add sampling info if this is is sampling option data (TODO: if needed decode sampling option data)
            #if 'option_description' in self.info[ip_src][ipfix_version][SourceID_str][template].keys():
        
            i += 1
        
        return True

    # Apply custom checks on IPFIX/NetFlow packet
    #  --> return False if packet needs to be discarded...
    def ipfix_custom_checks(self, ip_src, ipfix_packet):
        
        # Data Packet - v5
        if ipfix_packet.haslayer(NetflowHeaderV5):
            self.register_v5_info(ip_src, ipfix_packet)

        # Data Template(s) - v9, v10
        if ipfix_packet.haslayer(NetflowTemplateV9):                    
            self.register_data_template(ip_src, ipfix_packet)  

        # Option Template(s) - v9
        if ipfix_packet.haslayer(NetflowOptionsFlowsetV9):            
            self.register_option_templatev9(ip_src, ipfix_packet) 

        # Option Template(s) - v10
        if ipfix_packet.haslayer(NetflowOptionsFlowset10):            
            self.register_option_templatev10(ip_src, ipfix_packet) 

        # (Option-)Data Flowset(s) - v9, v10
        if ipfix_packet.haslayer(NetflowDataflowsetV9):              
            if not self.template_for_data_packet_exists(ip_src, ipfix_packet):
                return False  

        return True

    # Inspect packet by packet while:
    #   - removing data packets with no previously seen matching template
    #   - adding some info to traffic-info.json
    def inspect_and_cleanup(self):
        packets_new = []

        for packet in self.packets:

            # Add ip_src to self.info dict
            if IP in packet:
                ip_src = str(packet[IP].src)
            elif IPv6 in packet:
                ip_src = str(packet[IPv6].src)

            if str(ip_src) not in self.info.keys():
                self.info[str(ip_src)] = {}

            # Get Raw IPFIX/NetFlow payload
            ipfix_payload = packet[UDP].payload

            # Decode IPFIX/Netflow
            ipfix_packet = NetflowHeader(raw(ipfix_payload))

            #ipfix_packet.show()

            if self.ipfix_custom_checks(ip_src, ipfix_packet):
                packets_new.append(packet)
        
        self.packets = packets_new

    def adjust_timestamps(self, packets, inter_packet_delay):
        packets_new = []

        reference_time = EDecimal(1672534800.000)
        
        pkt_counter = 0
        for pkt in packets:
            pkt.time = reference_time + EDecimal(pkt_counter * inter_packet_delay)
            packets_new.append(pkt)
            pkt_counter += 1
        
        return packets_new

    def prep_for_repro(self, inter_packet_delay=0.001):

        # Gather Info and cleanup
        self.inspect_and_cleanup()

        # Randomize MAC addresses
        packets = ether_replace(self.packets)

        # Adjust timestamps
        packets = self.adjust_timestamps(packets, inter_packet_delay)

        logging.info(f"Size of processed IPFIX/NFv9 packets: {len(self.packets)}")
        return [self.info, packets]

