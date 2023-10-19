#
# Copyright(c) 2023 Swisscom (Schweiz) AG
# Authors: Marco Tollini, Leonardo Rodoni
# Distributed under the MIT License (http://opensource.org/licenses/MIT)
#

# Internal Libraries
import logging

# External Libraries
from scapy.all import Ether, IP, IPv6, TCP, Raw, raw

def get_layers(packet, do_print=False):
    layers = []
    counter = 0

    print("   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ---   ")
    while True:
        layer = packet.getlayer(counter)
        if layer is None: break
        layers.append(layer)
        
        if do_print:
            print(layer)
        counter += 1
        
    if do_print: print("Number of layers: ", counter)

    return layers

def tcp_fragment(packets):
    # Reconstruct packets (regenerate Ether/IP/TCP headers)
    packets_new = []

    # Process all sessions
    tcp_sessions = packets.sessions()
    for session_id, plist in tcp_sessions.items():

        logging.debug(f"Fragmenting TCP session [ID = {session_id}]")

        # Initial seq_nr for tcp session
        next_tcp_seq_nr = 1
        for packet in plist:
            
            # Get some IP header info info from packet
            if IP in packet:
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
            elif IPv6 in  packet:
                ip_src = packet[IPv6].src
                ip_dst = packet[IPv6].dst

            raw_payload = raw(packet[TCP].payload)

            while len(raw_payload) > 0:
              
                raw_payload_remaining = b''
                if len(raw_payload) > 1440:
                    raw_payload_remaining = raw_payload[1440:]
                    raw_payload = raw_payload[:1440]

                # Add raw_payload to TCP frame
                tcp_payload_size = len(raw_payload)
                flg = 0x02 if next_tcp_seq_nr == 1 else 0x18
                if IP in packet:
                    ether_frame = Ether() /\
                                  IP(src=ip_src, dst=ip_dst) /\
                                  TCP(seq=next_tcp_seq_nr, ack=next_tcp_seq_nr-1, flags=flg, dport=179) /\
                                  Raw(load=raw_payload)

                elif IPv6 in packet:
                    ether_frame = Ether() /\
                                  IPv6(src=ip_src, dst=ip_dst) /\
                                  TCP(seq=next_tcp_seq_nr, ack=next_tcp_seq_nr-1, flags=flg, dport=179) /\
                                  Raw(load=raw_payload)

                next_tcp_seq_nr += tcp_payload_size
                packets_new.append(ether_frame)

                raw_payload = raw_payload_remaining
              
    logging.debug(f"Size of fragmented packets: {len(packets_new)}")

    return packets_new

# Fare il merge aggiustando i timestamps ma mantenendo invariati gli inter-packet delays (perché quelli sono già aggiustati dalle singole 
#  processing functions! --> modifica solo inter protocol delays...
def merge_and_adjust_timestamps(packets):
    return packets