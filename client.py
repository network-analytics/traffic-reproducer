# External Libraries
import logging
from time import time, sleep

# Internal Libraries
from packet_manager import PacketWithMetadata
from report import report
from proto import Proto
from proto_client import BGPPClient, IPFIXPClient, BMPPClient

class Client:
    def __init__(
        self,
        queue_th,
        network_map,
        collectors,
        optimize_network,
        network_interface,
    ) -> None:
        self.job_queue = queue_th # can be None if no threading

        self.network_map = network_map
        self.collectors = collectors
        self.optimize_network = optimize_network
        self.network_interface = network_interface

        self.src_ip = network_map['src_ip']
        self.repro_ip = network_map['repro_ip']
        self.interface = network_interface
        self.so_sndbuf = optimize_network['so_sndbuf']
        self.so_rcvbuf = optimize_network['so_rcvbuf']

        self.pclients = {}

        if Proto.bgp.value in collectors:
            self._bgp_client_config()

        if Proto.bmp.value in collectors:
            self._bmp_client_config()

        if Proto.ipfix.value in collectors:
            self._ipfix_client_config()


    def _bgp_client_config(self):
        client_bgp = BGPPClient(
            self.collectors[Proto.bgp.value],
            self,
            self.network_map['bgp_id'],
            self.network_map['original_bgp_id'],
        )
        self.pclients[Proto.bgp.value] = client_bgp

    def _bmp_client_config(self):
        client_bmp = BMPPClient(
            self.collectors[Proto.bmp.value],
            self,
            #self.network_map['bgp_id'],
            #self.network_map['original_bgp_id'],
        )
        self.pclients[Proto.bmp.value] = client_bmp

    def _ipfix_client_config(self):
        client_ipfix = IPFIXPClient(
            self.collectors[Proto.ipfix.value],
            self,
        )
        self.pclients[Proto.ipfix.value] = client_ipfix

    def _send(self, packetwm: PacketWithMetadata):
        # no-threading
        proto = packetwm.type
        payload = self.get_payload(packetwm)
        return self.pclients[proto].send(payload, proto)

    # return True if the protocol manager decides the packet should not be sent
    def should_filter(self, packetwm: PacketWithMetadata):
        return self.pclients[packetwm.type].should_filter(packetwm)

    # Return the byte array that should be sent to the collector
    def get_payload(self, packetwm: PacketWithMetadata):
        proto = packetwm.type
        return self.pclients[proto].get_payload(packetwm)

    # helper for threading - running a thread
    def listen(self):
        while True:
            packetwm = self.job_queue.get(block=True)
            if packetwm is None:
                break # exit signal
            self._send(packetwm)

            qsize = self.job_queue.qsize()
            report.set_queue_size(qsize)
        logging.info(f'{self.repro_ip} thread exited')

    # reproduce a packet
    # If threading, then packet is put in a queue
    # Else, send packet
    # first_pkt tells if we already sent a packet or not
    # if not, we want to sync to the same bucket. We need to wait
    # the same amount of seconds from the minute as in the pcap
    def reproduce(self, packetwm: PacketWithMetadata, should_sync_ipfix):
        i = packetwm.number
        proto = packetwm.type

        if proto not in self.pclients:
            logging.critical(f"[{i}][{self.repro_ip}][{proto}] No clients found for protocol - SHOULD NEVER HAPPEN")
            return -1

        if self.should_filter(packetwm):
            logging.debug(f"[{i}][{self.repro_ip}][{proto}] Message will be filtered")
            return -1

        if should_sync_ipfix: # only runs once between all clients
            now_second_from_min = time() % 60
            pkt_second_from_min = int(packetwm.packet.time) % 60
            sleep_time = round((pkt_second_from_min-now_second_from_min) % 60, 3)
            while sleep_time > 0:
                logging.info(f"Waiting an additional {sleep_time}s to sync IPFIX to pmacct bucket")
                sleep(min(sleep_time, 1))
                sleep_time -= 1

        if self.job_queue is not None:
            # threading mode, add to queue
            self.job_queue.put(packetwm)
            # return 0 to signify that packet was not discared
            return 0

        return self._send(packetwm)
