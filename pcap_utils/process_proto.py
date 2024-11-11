# External Libraries
from scapy.all import rdpcap, PacketList
from pcap_utils.scapy_helpers import get_layers, ether_replace, adjust_timestamps
from abc import ABC, abstractmethod
import logging

# Internal Libraries
from pcap_utils.filter import filter_generator

class ProtoProcessing(ABC):
    def __init__(self, proto, pcap_file, selectors):
        self.info = {}
        self.proto = proto
        self.pcap_file = pcap_file
        self.selectors = selectors
        self.__proto_extract()

    def __proto_extract(self):
        # Extract packets with filter selectors

        packets_new = []

        # Load pcap in memory
        packets = rdpcap(self.pcap_file)
        logging.info(f"Size of packets: {len(packets)}")

        # Generate filter from selectors
        logging.debug(f"{self.proto} Selectors: {self.selectors}")
        proto_filter = filter_generator(self.selectors)

        for packet in packets:
            if proto_filter(packet):
                packets_new.append(packet)

        logging.debug(f"Size of filtered packets [{self.proto} selector]: {len(packets_new)}")

        self.packets = PacketList(packets_new)

    @classmethod
    def get_subclass(cls, proto, pcap_file, selectors):
        for c in cls.__subclasses__():
            if c.__name__ == proto.upper() + "Processing":
                break
        else:
            raise ValueError("Unknown Protocol: {!r}".format(proto))

        return c(proto, pcap_file, selectors)

    @abstractmethod
    def process_packets(self, **kwargs):
        pass

# Generic Protos
# - only supporting adjusting timestamps for now as preprocessing
class UDP_GENERICProcessing(ProtoProcessing):
    def process_packets(self, initial_delay=5, inter_packet_delay=0.001, tcp_payload_size=1424):
        self.packets = adjust_timestamps(self.packets, initial_delay, inter_packet_delay)
        logging.info(f"Size of processed UDP packets: {len(self.packets)}")
        return [None, self.packets]

class TCP_GENERICProcessing(ProtoProcessing):
    def process_packets(self, initial_delay=5, inter_packet_delay=0.001, tcp_payload_size=1424):
        self.packets = adjust_timestamps(self.packets, initial_delay, inter_packet_delay)
        logging.info(f"Size of processed TCP packets: {len(self.packets)}")
        return [None, self.packets]