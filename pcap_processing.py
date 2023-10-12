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
from random import randint, seed
from time import time, sleep
from prettytable import PrettyTable
from scapy.utils import wrpcap

# Internal Libraries
from proto import Proto
from pcap_utils.process_ipfix import IpfixProcessing

class PcapProcessing:
    # set inter packet and inter protocols delays according to config
    def __set_delays(self):
        if 'inter_packet_delay' in self.config['pcap_processing']:
            self.inter_packet_delay = self.config['pcap_processing']['inter_packet_delay']
        
        if 'inter_protocol_delay' in self.config['pcap_processing']:
            self.inter_protocol_delay = self.config['pcap_processing']['inter_protocol_delay']

    # set output filepaths based on input pcap name
    def __set_output_filepaths(self):
        if 'output_folder' in self.config['pcap_processing']:
            self.out_folder = self.config['pcap_processing']['output_folder']

        self.out_pcap = self.out_folder + "/traffic.pcap"
        self.out_config = self.out_folder + "/traffic-reproducer.yml"
        self.out_info = self.out_folder + "/traffic-info.json"

    # set random_seed (for pseudo anonymization)
    def __set_random_seed(self):
        if 'anonymize' in self.config['pcap_processing'] and self.config['pcap_processing']['anonymize']:
            logging.critical(f"[remember to remove seed(1)] random_seed = {self.random_seed}!") # TMP DEBUGGING
            seed(1) # TODO: only for debugging purposes, later on remove!!!
            self.random_seed = randint(0,65535)

    # create src_ip -> repro_ip mapping
    def __create_ip_map(self):
        table = PrettyTable(['src_ip'])
        ip_map = {}

        for m in self.config['network']['map']:
            ip_map[m['src_ip']] = m
            table.add_row([m['src_ip']])

        print(ip_map)
        self.ip_map = ip_map

    def __init__(self, config):
        self.out_info_dict = {}
        self.config = config

        # Defaults
        self.inter_packet_delay = 0.001
        self.inter_protocol_delay = 1
        self.random_seed = 0
        self.out_folder = os.path.splitext(self.config['pcap'])[0]

        self.__set_delays()
        self.__set_output_filepaths()
        self.__set_random_seed()
        self.__create_ip_map()

    def process_ipfix(self):
        logging.info("Processing IPFIX...")
        ipfix_p = IpfixProcessing(self)
        [info, packets] = ipfix_p.start()
        self.out_info_dict["IPFIX/NetFlow Information"] = info
        return packets

    def process_bgp(self):
        logging.info("Processing BGP...")

    def process_bmp(self):
        logging.info("Processing BMP...")

    def process(self, proto):
        if proto == 'ipfix': return self.process_ipfix()
        elif proto == 'bgp': return self.process_bgp()
        elif proto == 'bmp': return self.process_bmp()

    def start(self):
        logging.info(f"Input pcap file location:      {self.config['pcap']}") 
        logging.info("Starting pcap-file processing...")

        # Create output directory
        if not os.path.exists(self.out_folder):
            os.makedirs(self.out_folder)

        # TODO: if multiple pcap files are provided as input --> merge here...

        # process protocols following the order provided in config file
        supported_protos = [e.value for e in Proto]
        for proto in [proto for proto in self.config if proto in supported_protos]:
            packets = self.process(proto)   # have this return the scapy packet list object s.t. we can merge...

        # Merge the scapy packet object in the order given by selectors (with some default waiting times between the protocols)
        # --> we can do it in the for loop above directly
        # --> with some custom delay (e.g. if proto=bgp --> add 1s delay to the time s.t. next packet will be added after 1s)

        # Export processed packets
        wrpcap(self.out_pcap, packets)

        # Modify self.config [remove unused entries, add/modify needed ones, then publish it so self.out_config (dict to yml conversion)]
        # --> self.config will match (and used to produce) the traffic-reproducer.yml to be used for reproducing the processed pcap

        # Export and log out_info_json
        out_info_json = json.dumps(self.out_info_dict, indent = 3)
        with open(self.out_info, "w") as outfile:
            outfile.write(out_info_json)

        logging.info("Pcap processing successful!")
        logging.info(f"Pcap file location:            {self.out_pcap}") 
        logging.info(f"Config file location:          {self.out_config}") 
        logging.info(f"Info file location:            {self.out_info}") 

        return self.config
