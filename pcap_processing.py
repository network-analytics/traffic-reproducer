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
import json
import yaml
from time import time, sleep
from scapy.utils import wrpcap
from scapy.all import PacketList, EDecimal

# Internal Libraries
from proto import Proto
from pcap_utils.process_ipfix import IpfixProcessing
from pcap_utils.process_bgp import BGPProcessing
from pcap_utils.process_bmp import BMPProcessing

class PcapProcessing:

    def __init__(self, config):
        self.out_info_dict = {}
        self.config = config

        # Defaults
        self.inter_packet_delay = 0.001
        self.inter_protocol_delay = 1
        self.out_folder = os.path.splitext(self.config['pcap'])[0]

        self.__set_delays()
        self.__set_output_filepaths()

    # Set inter packet and inter protocols delays according to config
    def __set_delays(self):
        if 'inter_packet_delay' in self.config['pcap_processing']:
            self.inter_packet_delay = self.config['pcap_processing']['inter_packet_delay']
        
        if 'inter_protocol_delay' in self.config['pcap_processing']:
            self.inter_protocol_delay = self.config['pcap_processing']['inter_protocol_delay']

    # Set output filepaths based on input pcap name (or if provided from output_folder config key)
    def __set_output_filepaths(self):
        if 'output_folder' in self.config['pcap_processing']:
            self.out_folder = self.config['pcap_processing']['output_folder']

        self.out_pcap = self.out_folder + "/traffic.pcap"
        self.out_config = self.out_folder + "/traffic-reproducer.yml"
        self.out_info = self.out_folder + "/traffic-info.json"

    def process_ipfix(self):
        logging.info("Processing IPFIX...")
        ipfix_p = IpfixProcessing(self.config['pcap'], 
                                  self.config['IPFIX']['select'])

        [info, packets] = ipfix_p.prep_for_repro(self.inter_packet_delay)
                                                 
        self.out_info_dict["IPFIX/NetFlow Information"] = info

        # Keep only port filter for repro
        self.config['IPFIX']['select'].pop('ip', None)
        self.config['IPFIX']['select'].pop('cflow', None)

        return packets

    def process_bgp(self):
        logging.info("Processing BGP...")
        bgp_p = BGPProcessing(self.config['pcap'], 
                              self.config['BGP']['select'])

        [info, packets] = bgp_p.prep_for_repro(self.inter_packet_delay)

        self.out_info_dict["BGP Information"] = info

        # Keep only port filter for repro
        self.config['BGP']['select'].pop('ip', None)
        self.config['BGP']['select'].pop('bgp', None)

        return packets

    def process_bmp(self):
        logging.info("Processing BMP...")
        bmp_p = BMPProcessing(self.config['pcap'], 
                              self.config['BMP']['select'])

        [info, packets] = bmp_p.prep_for_repro(self.inter_packet_delay)

        self.out_info_dict["BMP Information"] = info

        # Keep only port filter for repro
        self.config['BMP']['select'].pop('ip', None)
        self.config['BMP']['select'].pop('bmp', None)

        return packets

    def process_proto(self, proto_name):
        if proto_name == 'IPFIX': return self.process_ipfix()
        elif proto_name == 'BGP': return self.process_bgp()
        elif proto_name == 'BMP': return self.process_bmp()
  
    
    def adapt_config_for_repro(self):
        # Remove pcap_processing section
        self.config.pop('pcap_processing')

        # Set processed pcap location
        self.config['pcap'] = self.out_pcap

        # TODO: add some of the defaults if they're missing

    def adjust_timestamps(self, packets, last_protocol_pkt_time):
        # Reference time for delay handling
        reference_time = EDecimal(1672534800.000)

        packets_new = []

        for packet in packets:
            packet.time = packet.time + (last_protocol_pkt_time-reference_time) + EDecimal(self.inter_protocol_delay)
            packets_new.append(packet)

        return packets_new

    def start(self):
        logging.info(f"Input pcap file location:      {self.config['pcap']}") 
        logging.info("Starting pcap-file processing...")

        # Create output directory
        if not os.path.exists(self.out_folder):
            os.makedirs(self.out_folder)

        # Process protocols in the order provided in config file
        supported_protos = [e.value for e in Proto]
        packets = []
        for proto in [proto for proto in self.config if proto in supported_protos]:

            proto_packets = self.process_proto(proto)

            if packets:
                proto_packets = self.adjust_timestamps(proto_packets, packets[-1].time)

            packets += proto_packets 

        # Export processed packets
        wrpcap(self.out_pcap, packets)

        # Adapt config file for reproducing and export
        self.adapt_config_for_repro()
        print(self.config)
        file=open(self.out_config, "w")
        yaml.dump(self.config, file, sort_keys=False)
        file.close()

        # Export out_info_json
        out_info_json = json.dumps(self.out_info_dict, indent = 3)
        with open(self.out_info, "w") as outfile:
            outfile.write(out_info_json)

        logging.info("Pcap processing successful!")
        logging.info(f"Size of processed packet (all protocols):  {len(packets)}")
        logging.info(f"Pcap file location:                        {self.out_pcap}") 
        logging.info(f"Config file location:                      {self.out_config}") 
        logging.info(f"Info file location:                        {self.out_info}") 

        return self.config
