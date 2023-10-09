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
from scapy.all import IP, IPv6, raw
from scapy.all import rdpcap
from scapy.layers.netflow import *

# Internal Libraries
from pcap_tools.filter import filter_generator

class IpfixProcessing:
    def __init__(self, pp_data):

        # Info about templates, ips, amount of messages
        # { v10: { TEMPLATE_ID: {TEMPLATE_INFO}}}
        self.info = {}

        # Some parameters from PcapProcessing Class
        self.config = pp_data.config
        self.inter_packet_delay = pp_data.inter_packet_delay
        self.random_seed = pp_data.random_seed
        self.ip_map = pp_data.ip_map
    
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

        #ipfix_packet.show()
        #print("   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ")
        #self.__get_layers(ipfix_packet, True)

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

        #ipfix_packet.show()
        #print("   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ")
        #self.__get_layers(ipfix_packet, True)

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

        #ipfix_packet.show()
        #print("   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ")
        #self.__get_layers(ipfix_packet, True)

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
        
        # TODO: also here we need to support iteration on flowsets with while loop!
        # --> iterate on NetflowDataflowsetV9

        #ipfix_packet.show()
        # TMP Get IPFIX/NetFlow Layers (helper for development)
        #print("   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ")
        #self.__get_layers(ipfix_packet, True)

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

        # Version check (TODO: add this to the filtering!)
        if ipfix_packet.version not in self.config['ipfix']['include']['ipfix_versions']:
            return False
        
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


    # - remove data packets with no previously seen matching template
    # - get some info for traffic-info.json
    def inspect_and_cleanup(self, packets):
        packets_new = []

        for packet in packets:

            # Get IPFIX/NetFlow payload
            if IP in packet:
                ip_src = str(packet[IP].src)
                ipfix_payload = packet[IP].payload.payload
            elif IPv6 in packet:
                ip_src = str(packet[IPv6].src)
                ipfix_payload = packet[IPv6].payload.payload

            # Decode IPFIX/Netflow
            ipfix_packet = NetflowHeader(raw(ipfix_payload))

            # TMP LOGGING FOR DEBUGGING
            #ipfix_packet.show()
            # TMP Get IPFIX/NetFlow Layers (helper for development)
            #print("   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ")
            #self.__get_layers(ipfix_packet, True)

            if self.ipfix_custom_checks(ip_src, ipfix_packet):
                packets_new.append(packet)
        
        return packets_new

    # Extract IPFIX/NetFlow packets
    def extract_ipfix_packets(self, packets):
        packets_new = []

        for packet in packets:
            if IP in packet:
                ip_src = packet[IP].src
            elif IPv6 in packet:
                ip_src = packet[IPv6].src
            
            proto_filter = filter_generator(self.config['ipfix']['select'])

            if proto_filter(packet) and ip_src in self.ip_map:
                packets_new.append(packet)

                # Add ip_src to self.info dict
                if str(ip_src) not in self.info.keys():
                    self.info[str(ip_src)] = {}


        return packets_new


    def start(self):

        # Load pcap in memory
        packets = rdpcap(self.config['pcap'])
        logging.info(f"Size of packets: {len(packets)}") 

        # Extract IPFIX/NetFlow packets and defragment
        packets = self.extract_ipfix_packets(packets)
        logging.info(f"Size of ipfix packets: {len(packets)}")
        packets = netflowv9_defragment(packets)
        logging.info(f"Size of ipfix packets defragmented: {len(packets)}")

        # Start processing
        packets = self.inspect_and_cleanup(packets)

        logging.info(f"Size of ipfix packets processed: {len(packets)}") 

        return [self.info, packets]

