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
        client):

        super().__init__(
            collector,
            client,
            socket.socket(socket.AF_INET))
        
        self.proto = Proto.bgp.value

        # Overwrite socket if repro_ip is ipv6 
        # TODO: handle this in a better way in the __init stuff above
        if type(ipaddress.ip_address(self.client.repro_ip)) is ipaddress.IPv6Address:
            self.socket = socket.socket(socket.AF_INET6)

    def get_payload(self, packetwm: PacketWithMetadata):
        packet = packetwm.packet
        payload = raw(packet[TCP].payload)
        return payload

    def send(self, packet, proto):
        r = super().send(packet, proto)
        return r

class BMPPClient(GenericPClient):
    def __init__(
        self,
        collector,
        client):

        super().__init__(
            collector,
            client,
            socket.socket(socket.AF_INET))

        self.proto = Proto.bmp.value        

        # Overwrite socket if repro_ip is ipv6
        if type(ipaddress.ip_address(self.client.repro_ip)) is ipaddress.IPv6Address:
            self.socket = socket.socket(socket.AF_INET6)

    def get_payload(self, packetwm: PacketWithMetadata):
        packet = packetwm.packet
        payload = raw(packet[TCP].payload)
        return raw(packet[TCP].payload)



class IPFIXPClient(GenericPClient):
    def __init__(
        self,
        collector,
        client):

        super().__init__(
            collector,
            client,
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM))

        self.proto = Proto.ipfix.value        

        # Overwrite socket if repro_ip is ipv6
        if type(ipaddress.ip_address(self.client.repro_ip)) is ipaddress.IPv6Address:
            self.socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

    # Have a look at this if we are using that or we can remove or we need to do it on the preprocessing
    # This if it replaces export time with current time it probably makes sense to keep
    # --> and also investigate if it might make sense to implement it for BMP and BGP
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

    def get_payload(self, packetwm: PacketWithMetadata):
        ipfix_payload = self._ipfix_replace_export_time(packetwm)
        return ipfix_payload
