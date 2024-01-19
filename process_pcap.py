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
from pcap_utils.process_proto import ProtoProcessing
from pcap_utils.process_ipfix import IPFIXProcessing
from pcap_utils.process_bgp import BGPProcessing
from pcap_utils.process_bmp import BMPProcessing

class PcapProcessing:

    def __init__(self, config):
        self.out_info_dict = {}
        self.config = config

        # Defaults
        self.initial_delay = 5
        self.inter_packet_delay = 0.001
        self.inter_protocol_delay = 1
        self.out_folder = os.path.splitext(self.config['pcap'])[0]

        if 'pcap_processing' in config:
            self.__set_args_from_config()

        self.out_pcap = self.out_folder + "/traffic.pcap"
        self.out_config = self.out_folder + "/traffic-reproducer.yml"
        self.out_info = self.out_folder + "/traffic-info.json"

        self.__print_args()

    # Set inter packet and inter protocols delays according to config
    def __set_args_from_config(self):
        if 'initial_delay' in self.config['pcap_processing']:
            self.initial_delay = self.config['pcap_processing']['initial_delay']

        if 'inter_packet_delay' in self.config['pcap_processing']:
            self.inter_packet_delay = self.config['pcap_processing']['inter_packet_delay']
        
        if 'inter_protocol_delay' in self.config['pcap_processing']:
            self.inter_protocol_delay = self.config['pcap_processing']['inter_protocol_delay']

        if 'output_folder' in self.config['pcap_processing']:
            self.out_folder = self.config['pcap_processing']['output_folder']

    def __print_args(self):
        logging.info(" ")
        logging.info("    ** Pcap-file processing arguments: **")
        logging.info(f"    input_pcap = {self.config['pcap']}") 
        logging.info(f"    out_folder = {self.out_folder}")
        logging.info(f"    initial_delay = {self.initial_delay}")
        logging.info(f"    inter_packet_delay = {self.inter_packet_delay}")
        logging.info(f"    inter_protocol_delay = {self.inter_protocol_delay}")
        logging.info(" ")
    
    def adapt_config_for_repro(self, src_ips):
        # Remove pcap_processing section
        self.config.pop('pcap_processing', None)

        # Set processed pcap location
        self.config['pcap'] = self.out_pcap

        # Add some of the defaults if they're missing
        if 'time_factor' not in self.config:
            self.config['time_factor'] = 1
        if 'keep_open' not in self.config:
            self.config['keep_open'] = False
        if 'no_sync' not in self.config:
            self.config['no_sync'] = False
        if 'optimize' not in self.config:
            self.config['optimize'] = {'threading': False, \
                                       'preload': False,
                                       'network': {'so_sndbuf': None, \
                                                   'so_rcvbuf': None}}
        if 'network' not in self.config:
            if src_ips: 
                for src_ip in src_ips:
                    self.config['network'] = {'interface': None, \
                                              'map': {'src_ip': src_ip, \
                                                      'repro_ip': '<MISSING_PARAM>'}}
            else: 
                self.config['network'] = {'interface': None, \
                                          'map': {'src_ip': '<MISSING_PARAM>', \
                                                  'repro_ip': '<MISSING_PARAM>'}}
                                                      

    def adjust_timestamps(self, packets, last_protocol_pkt_time):
        # Reference time for delay handling
        reference_time = EDecimal(self.initial_delay + 1672534800.000)

        packets_new = []

        for packet in packets:
            packet.time = packet.time + (last_protocol_pkt_time-reference_time) + EDecimal(self.inter_protocol_delay)
            packets_new.append(packet)

        return packets_new

    def start(self):
        logging.info("Starting pcap-file processing...")

        # Create output directory
        if not os.path.exists(self.out_folder):
            os.makedirs(self.out_folder)

        # Process protocols in the order provided in config file
        supported_protos = [e.value for e in Proto]
        packets = []
        src_ips = []
        for proto in [proto for proto in self.config if proto in supported_protos]:

            logging.info(f"Processing {proto}")
            pp = ProtoProcessing.get_subclass(proto, 
                                              self.config['pcap'], 
                                              self.config[proto]['select'])

            [info, proto_packets] = pp.prep_for_repro(self.initial_delay, self.inter_packet_delay)                                                
            self.out_info_dict[proto.upper() + " Information"] = info

            # Adjust (proto-specific) config for parameters reproduction
            if 'collector' not in self.config[proto]:
                self.config[proto]['collector'] = {'ip': '<MISSING_PARAM>','port': '<MISSING_PARAM>'}

            # Get src ips if defined in selectors
            if 'ip' in self.config[proto]['select'] and 'src' in self.config[proto]['select']['ip']:
                src_ips = list(set(src_ips + [ip for ip in self.config[proto]['select']['ip']['src']]))

            # Pop selectors
            self.config[proto].pop('select', None)

            if packets:
                proto_packets = self.adjust_timestamps(proto_packets, packets[-1].time)

            packets += proto_packets 

        # Export processed packets
        wrpcap(self.out_pcap, packets)

        # Adjust (generic) config parameters for repro
        self.adapt_config_for_repro(src_ips)
        #print(self.config)
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
