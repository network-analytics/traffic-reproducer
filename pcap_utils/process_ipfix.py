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
from scapy.layers.netflow import *

# Internal Libraries
from pcap_utils.filter import filter_generator

class IpfixProcessing:
    def __init__(self, pcap_file, ipfix_selectors, inter_packet_delay, random_seed):

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
        return layers

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

            i = i + 1

    def template_for_data_packet_exists(self, ip_src, ipfix_packet):

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
    def inspect_and_cleanup(self, packets):
        packets_new = []

        for packet in packets:

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
            # TMP Get IPFIX/NetFlow Layers (helper for development)
            #print("   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ")
            #self.__get_layers(ipfix_packet, True)

            if self.ipfix_custom_checks(ip_src, ipfix_packet):
                packets_new.append(packet)
        
        return packets_new

    # Extract IPFIX/NetFlow packets with selectors
    def extract_ipfix_packets(self, packets):
        packets_new = []

        # Generate filter from selectors
        logging.debug(f"ipfix_selectors: {self.ipfix_selectors}")
        proto_filter = filter_generator(self.ipfix_selectors)

        for packet in packets:
            
            if proto_filter(packet):
                packets_new.append(packet)

        return packets_new

    def start(self):

        # Load pcap in memory
        packets = rdpcap(self.pcap_file)
        logging.info(f"Size of packets: {len(packets)}") 

        # Extract IPFIX/NetFlow packets and defragment
        packets = self.extract_ipfix_packets(packets)
        logging.debug(f"Size of ipfix packets: {len(packets)}")
        packets = netflowv9_defragment(packets)
        logging.debug(f"Size of ipfix packets defragmented: {len(packets)}")

        # Start processing
        packets = self.inspect_and_cleanup(packets)

        logging.info(f"Size of ipfix packets processed: {len(packets)}") 

        return [self.info, packets]
