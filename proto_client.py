# External Libraries
import ipaddress
import logging
import socket
import threading
import select
from time import time
from scapy.all import TCP, UDP, raw

# Internal Libraries
from packet_manager import PacketWithMetadata
from bgp import is_bgp_open_message
from bmp import is_bmp_open_message
from proto import Proto
from report import report

class GenericPClient:
    def __init__(
        self,
        collector,
        client,
        socket,
    ):
        self.proto = "unknown"
        self.collector = collector
        self.socket = socket
        self.socket_init = False
        self.client = client
        self.receiving_thread = None
        self.should_run = True

    def should_filter(self, packetwm: PacketWithMetadata):
        raise Exception("Method not implemented")

    def get_payload(self, packetwm: PacketWithMetadata):
        raise Exception("Method not implemented")

    def get_repro_ip(self):
      return ipaddress.ip_address(self.client.repro_ip)

    def receiver(self):
        while self.should_run:
            ready = select.select([self.socket], [], [], 1)
            if ready[0]:
                buff = self.socket.recv(4096)
                if len(buff) > 0:
                    logging.info(f"Received {len(buff)} bytes")

    def _init_socket(self):
        self.socket_init = True
        # socket has already a socket initialized with the right proto (UDP or TCP)
        s = self.socket
        # set options
        if self.client.interface is not None:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, str(self.client.interface + '\0').encode('utf-8'))
        if self.client.so_sndbuf is not None:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.client.so_sndbuf)
        if self.client.so_rcvbuf is not None:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.client.so_rcvbuf)

        logging.info(f'[{self.client.repro_ip}][{self.proto}] Opening socket with collector (simulating {self.client.src_ip})')

        if type(ipaddress.ip_address(self.client.repro_ip)) is ipaddress.IPv4Address:
          s.bind((self.client.repro_ip, 0))
        else: # IPv6
          s.bind((self.client.repro_ip, 0, 0, 0)) # check: do we really need a 4-tuple?
      
        s.connect((self.collector['ip'], self.collector['port']))

        self.socket = s

        self.receiving_thread = threading.Thread(target=self.receiver)
        self.receiving_thread.start()

    def send(self, packet, proto):
        if not self.socket_init:
            # Open socket
            self._init_socket()
        report.pkt_proto_sent_countup(proto)
        # print(packet.hex())
        return self.socket.send(packet)


class BGPPClient(GenericPClient):
    def __init__(
        self,
        collector,
        client,
        bgp_id,
        original_bgp_id,
    ):

        super().__init__(
            collector,
            client,
            socket.socket(socket.AF_INET)
        )
        
        # Overwrite socket if repro_ip is ipv6
        if type(ipaddress.ip_address(self.client.repro_ip)) is ipaddress.IPv6Address:
            self.socket = socket.socket(socket.AF_INET6)

        self.bgp_id = bgp_id
        self.original_bgp_id = original_bgp_id
        self.found_first_open_msg = False
        self.proto = Proto.bgp.value

        self.is_capabilities_received = False

    def _bgp_open_replace_bgpid(self, packetwm: PacketWithMetadata):
        # this is open, we need to change the bgp id
        packet = packetwm.packet
        i = packetwm.number
        pkt_raw = raw(packet[TCP].payload)
        pcap_bgp_id = ipaddress.ip_address(int.from_bytes(pkt_raw[24:28], 'big', signed=False))
        bgp_id_b = int(ipaddress.ip_address(self.bgp_id)).to_bytes(4, 'big', signed=False)
        open_msg = pkt_raw[:24] + bgp_id_b + pkt_raw[28:]
        logging.info(f"[{i}][{self.client.repro_ip}] BGP ID in open message for {self.client.repro_ip} will change from {pcap_bgp_id} to {self.bgp_id}")
        return open_msg

    def is_first_open_msg_found(self):
        return self.found_first_open_msg

    def should_filter(self, packetwm: PacketWithMetadata):
        packet = packetwm.packet
        i = packetwm.number
        if not self.found_first_open_msg:
            payload = raw(packet[TCP].payload)
            if not is_bgp_open_message(payload, self.original_bgp_id):
                # Not got a first open message
                logging.debug(f"[{i}][{self.client.repro_ip}] Discarding packet as no BGP Open yet")
                report.pkt_proto_filtered_countup(self.proto)
                return True
            # First open message!
            logging.info(f"[{i}][{self.client.repro_ip}] First BGP Open found")
            self.found_first_open_msg = True
        return False

    def get_payload(self, packetwm: PacketWithMetadata):
        packet = packetwm.packet
        payload = raw(packet[TCP].payload)
        if is_bgp_open_message(payload, self.original_bgp_id):
            return self._bgp_open_replace_bgpid(packetwm)
        return payload

    def send(self, packet, proto):
        r = super().send(packet, proto)

        # if not self.is_capabilities_received:
        #     self.is_capabilities_received = True
        #     data = self.socket.recv(4000)
        #     logging.info(f"Received {len(data)} bytes")

        return r

class BMPPClient(GenericPClient):
    def __init__(
        self,
        collector,
        client,
    ):
        super().__init__(
            collector,
            client,
            socket.socket(socket.AF_INET)
        )
        
        # Overwrite socket if repro_ip is ipv6
        if type(ipaddress.ip_address(self.client.repro_ip)) is ipaddress.IPv6Address:
            self.socket = socket.socket(socket.AF_INET6)
        self.proto = Proto.bmp.value

    def should_filter(self, packetwm: PacketWithMetadata):
        return False

    def get_payload(self, packetwm: PacketWithMetadata):
        packet = packetwm.packet
        payload = raw(packet[TCP].payload)
        return raw(packet[TCP].payload)



class IPFIXPClient(GenericPClient):
    def __init__(
        self,
        collector,
        client,
    ):
        super().__init__(
            collector,
            client,
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        )
        
        # Overwrite socket if repro_ip is ipv6
        if type(ipaddress.ip_address(self.client.repro_ip)) is ipaddress.IPv6Address:
            self.socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

  
        self.proto = Proto.ipfix.value

    def _ipfix_replace_export_time(self, packetwm: PacketWithMetadata):
        packet = packetwm.packet
        i = packetwm.number
        raw_pkt = raw(packet[UDP].payload)
        pkt_time = packet.time
        exp_time = int.from_bytes(raw_pkt[8:12], 'big', signed=False)
        diff_time = int(pkt_time) - exp_time

        curr_time = int(time())
        replaced_time = curr_time - diff_time
        mod_raw_pkt = raw_pkt[:8] + replaced_time.to_bytes(4, 'big') + raw_pkt[12:]

        return mod_raw_pkt

    def should_filter(self, packetwm: PacketWithMetadata):
        pclients = self.client.pclients
        if (Proto.bgp.value in pclients and not pclients[Proto.bgp.value].is_first_open_msg_found()):
            logging.debug(f"[{packetwm.number}][{self.client.repro_ip}] First BGP OPEN for peer not found")
            report.pkt_proto_filtered_countup(self.proto)
            return True
        return False

    def get_payload(self, packetwm: PacketWithMetadata):
        ipfix_payload = self._ipfix_replace_export_time(packetwm)
        return ipfix_payload
