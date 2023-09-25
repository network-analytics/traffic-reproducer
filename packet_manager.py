# External Libraries
import logging
from scapy.all import PcapReader, rdpcap

# Internal Libraries
from report import report
from proto import Proto

class PacketWithMetadata:
    def __init__(self, number, packet, typ: Proto) -> None:
        self.number = number
        self.packet = packet
        self.type = typ


class PacketManager:
    def __init__(self, pcap_path, selectors, preload=True):
        self.pcap_path = pcap_path
        self.preload = preload

        self.selectors = selectors

        self.reader = None
        self.reader_i = 0
        self.current_packet = 0

    def _transform(self, packet):
        for protos in self.selectors:
            if self.selectors[protos](packet):
                return PacketWithMetadata(number=self.current_packet, packet=packet, typ=protos)

        logging.debug(f"[{self.current_packet}] discarded as proto was not selected")
        report.pkt_noproto_countup()
        return None


    def __iter__(self):
        self.current_packet = 0

        # if not preload, use pcapreader, which reads packet by packet
        if not self.preload:
            logging.info('Preload is disabled')
            self.reader = iter(PcapReader(self.pcap_path))
            return self

        # if preload, load, filter, and give type to all packets
        logging.info('Preload is enabled - loading, filtering and preprocessing all packets - this might take a while')
        packets = rdpcap(self.pcap_path)
        logging.info('preload process: pcap loaded into the memory')
        self.reader = []
        self.reader_i = 0
        for packet in packets:
            if self.current_packet % 10000 == 0:
                logging.info(f'preload process: processed {self.current_packet}/{len(packets)} packets')
            self.current_packet += 1

            packetwm = self._transform(packet) # null if packet is filtered
            if packetwm is None:
                continue

            self.reader.append(packetwm)

        logging.info(f'Preload done: {len(self.reader)} packets after filters')

        return self


    def __next__(self) -> PacketWithMetadata:
        if not self.preload:
            while True:
                self.current_packet += 1
                packet = next(self.reader) # raises StopIteration

                packetwm = self._transform(packet) # null if packet is filtered
                if packetwm is not None:
                    return packetwm
        else:
            if self.reader_i >= len(self.reader):
                raise StopIteration

            packetwm = self.reader[self.reader_i]
            self.reader_i += 1
            return packetwm
