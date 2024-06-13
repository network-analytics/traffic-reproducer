#
# Copyright(c) 2023 Swisscom (Schweiz) AG
# Authors: Marco Tollini, Leonardo Rodoni
# Distributed under the MIT License (http://opensource.org/licenses/MIT)
#

# External Libraries
import ipaddress
import logging
import socket
import threading
import select
from scapy.all import TCP, UDP, raw

# Internal Libraries
from packet_manager import PacketWithMetadata
from proto import Proto
from report import report

class GenericPClient:
    def __init__(
        self,
        collector,
        client):

        self.proto = "unknown"
        self.collector = collector
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

        # socket has already a socket initialized by one the child classes with the right proto (UDP or TCP)
        s = self.socket

        # set additional socket options
        if self.client.interface is not None:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, str(self.client.interface + '\0').encode('utf-8'))
        if self.client.so_sndbuf is not None:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.client.so_sndbuf)
        if self.client.so_rcvbuf is not None:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.client.so_rcvbuf)

        # some logs
        logging.info(f'[{self.client.repro_ip}][{self.proto}] Opening socket with collector (simulating {self.client.src_ip})')

        # bind and connect to socket
        if type(ipaddress.ip_address(self.client.repro_ip)) is ipaddress.IPv4Address:
            s.bind((self.client.repro_ip, 0))
        elif type(ipaddress.ip_address(self.client.repro_ip)) is ipaddress.IPv6Address:
            s.bind((self.client.repro_ip, 0, 0, 0))
        s.connect((self.collector['ip'], self.collector['port']))

        self.socket = s
        self.receiving_thread = threading.Thread(target=self.receiver)
        self.receiving_thread.start()

    def send(self, packet, proto):
        # open socket if it's the first packet
        if not self.socket_init:
            self._init_socket()

        report.pkt_proto_sent_countup(proto)
        return self.socket.send(packet)

class GenericTCPPClient(GenericPClient):
    def __init__(
        self,
        collector,
        client):

        super().__init__(
            collector,
            client)

        self.__init_socket()  # initialize TCP socket
        self.proto = Proto.tcp_generic.value        

    def __init_socket(self):
        if type(ipaddress.ip_address(self.client.repro_ip)) is ipaddress.IPv4Address:
            self.socket = socket.socket(socket.AF_INET)
        elif type(ipaddress.ip_address(self.client.repro_ip)) is ipaddress.IPv6Address:
            self.socket = socket.socket(socket.AF_INET6)

    def get_payload(self, packetwm: PacketWithMetadata):
        packet = packetwm.packet
        tcp_payload = raw(packet[TCP].payload)
        return tcp_payload

class GenericUDPPClient(GenericPClient):
    def __init__(
        self,
        collector,
        client):

        super().__init__(
            collector,
            client)

        self.__init_socket()  # initialize UDP socket
        self.proto = Proto.udp_generic.value        

    def __init_socket(self):
        if type(ipaddress.ip_address(self.client.repro_ip)) is ipaddress.IPv4Address:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif type(ipaddress.ip_address(self.client.repro_ip)) is ipaddress.IPv6Address:
            self.socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

    def get_payload(self, packetwm: PacketWithMetadata):
        packet = packetwm.packet
        ipfix_packet = raw(packet[UDP].payload)
        return ipfix_packet

class BGPPClient(GenericPClient):
    def __init__(
        self,
        collector,
        client):

        super().__init__(
            collector,
            client)

        self.__init_socket()  # initialize TCP socket
        self.proto = Proto.bgp.value

    def __init_socket(self):
        if type(ipaddress.ip_address(self.client.repro_ip)) is ipaddress.IPv4Address:
            self.socket = socket.socket(socket.AF_INET)
        elif type(ipaddress.ip_address(self.client.repro_ip)) is ipaddress.IPv6Address:
            self.socket = socket.socket(socket.AF_INET6)

    def get_payload(self, packetwm: PacketWithMetadata):
        packet = packetwm.packet
        bgp_packet = raw(packet[TCP].payload)
        return bgp_packet

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
            client)

        self.__init_socket()  # initialize TCP socket
        self.proto = Proto.bmp.value        

    def __init_socket(self):
        if type(ipaddress.ip_address(self.client.repro_ip)) is ipaddress.IPv4Address:
            self.socket = socket.socket(socket.AF_INET)
        elif type(ipaddress.ip_address(self.client.repro_ip)) is ipaddress.IPv6Address:
            self.socket = socket.socket(socket.AF_INET6)

    def get_payload(self, packetwm: PacketWithMetadata):
        packet = packetwm.packet
        bmp_packet = raw(packet[TCP].payload)
        return bmp_packet

class IPFIXPClient(GenericPClient):
    def __init__(
        self,
        collector,
        client):

        super().__init__(
            collector,
            client)

        self.__init_socket()  # initialize UDP socket
        self.proto = Proto.ipfix.value        

    def __init_socket(self):
        if type(ipaddress.ip_address(self.client.repro_ip)) is ipaddress.IPv4Address:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        elif type(ipaddress.ip_address(self.client.repro_ip)) is ipaddress.IPv6Address:
            self.socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

    def get_payload(self, packetwm: PacketWithMetadata):
        packet = packetwm.packet
        ipfix_packet = raw(packet[UDP].payload)
        return ipfix_packet
