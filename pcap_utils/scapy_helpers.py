#
# Copyright(c) 2023 Swisscom (Schweiz) AG
# Authors: Marco Tollini, Leonardo Rodoni
# Distributed under the MIT License (http://opensource.org/licenses/MIT)
#

# Internal Libraries
import logging, random

# External Libraries
from scapy.all import Ether, IP, IPv6, TCP, Raw, raw, EDecimal, PacketList

def get_layers(packet, do_print=False, layer_limit=100):
    layers = []
    counter = 0

    while (counter < layer_limit):
        layer = packet.getlayer(counter)
        if layer is None: break
        layers.append(layer.name)
        counter += 1
        
    if do_print: print(layers)

    return layers

def adjust_timestamps(packets, initial_delay, inter_packet_delay):
    # Replace all packets timestamp starting from reference with some inter-packet delay
    packets_new = []
    reference_time = EDecimal(initial_delay + 1672534800.000)
    pkt_counter = 0

    for pkt in packets:
        pkt.time = reference_time + EDecimal(pkt_counter * inter_packet_delay)
        packets_new.append(pkt)
        pkt_counter += 1
    
    return PacketList(packets_new)

def ether_replace(packets):
    # Replace src and dst MAC address with random ones
    packets_new = []

    src_mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                           random.randint(0, 255),
                                           random.randint(0, 255))
    dst_mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                           random.randint(0, 255),
                                           random.randint(0, 255))

    for packet in packets:
        packet[Ether].src = src_mac
        packet[Ether].dst = dst_mac
        packets_new.append(packet)
    
    return packets_new

def tcp_fragment(packets, tcp_port):
    # This function fragments packets longer that 1500bytes MTU
    # (TCP payload < 1424)

    # Reconstruct packets (regenerate Ether/IP/TCP headers)
    packets_new = []

    # Process all sessions
    tcp_sessions = packets.sessions()
    for session_id, plist in tcp_sessions.items():
        src_mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                               random.randint(0, 255),
                                               random.randint(0, 255))
        dst_mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                               random.randint(0, 255),
                                               random.randint(0, 255))

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
                if len(raw_payload) > 1424:
                    raw_payload_remaining = raw_payload[1424:]
                    raw_payload = raw_payload[:1424]

                # Add raw_payload to TCP frame
                tcp_payload_size = len(raw_payload)
                flg = 0x02 if next_tcp_seq_nr == 1 else 0x18
                if IP in packet:
                    ether_frame = Ether(src=src_mac, dst=dst_mac) /\
                                  IP(src=ip_src, dst=ip_dst) /\
                                  TCP(seq=next_tcp_seq_nr, ack=next_tcp_seq_nr-1, flags=flg, dport=tcp_port) /\
                                  Raw(load=raw_payload)

                elif IPv6 in packet:
                    ether_frame = Ether(src=src_mac, dst=dst_mac) /\
                                  IPv6(src=ip_src, dst=ip_dst) /\
                                  TCP(seq=next_tcp_seq_nr, ack=next_tcp_seq_nr-1, flags=flg, dport=tcp_port) /\
                                  Raw(load=raw_payload)

                next_tcp_seq_nr += tcp_payload_size
                packets_new.append(ether_frame)

                raw_payload = raw_payload_remaining
              
    logging.debug(f"Size of fragmented packets: {len(packets_new)}")

    return packets_new

def tcp_build(payloads, ip_ver, ip_src, ip_dst, tcp_port, tcp_seq_nr=1, tcp_payload_size=1424):
    # Construct packets (generate Ether/IP/TCP headers based on input arguments)
    # This function will try to keep TCP payload len ~= tcp_payload_size (default=1424 s.t. MTU ~=< 1500),
    # but if there are single payloads that are > tcp_payload_size this function does not fragment
    # --> If you want to make sure they're strictly < tcp_payload_size, then
    # s    call tcp_fragment() after calling this function

    packets_new = []
    src_mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                           random.randint(0, 255),
                                           random.randint(0, 255))
    dst_mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                           random.randint(0, 255),
                                           random.randint(0, 255))

    prev_len = 0
    prev_payload = b''
    next_tcp_seq_nr = tcp_seq_nr

    for payload in payloads:
        
        raw_payload = raw(payload)
        raw_len = len(raw_payload)

        if raw_len + prev_len < tcp_payload_size or \
           (prev_len == 0 and raw_len > tcp_payload_size):

            prev_payload += raw_payload
            prev_len += raw_len

        else:
            # Build TCP packet for prev_payload
            flg = 0x02 if next_tcp_seq_nr == 1 else 0x18   
            
            if ip_ver == 4:
                ether_frame = Ether(src=src_mac, dst=dst_mac) /\
                              IP(src=ip_src, dst=ip_dst) /\
                              TCP(seq=next_tcp_seq_nr, ack=next_tcp_seq_nr-1, flags=flg, dport=tcp_port) /\
                              Raw(load=prev_payload)

            elif ip_ver == 6:
                ether_frame = Ether(src=src_mac, dst=dst_mac) /\
                              IPv6(src=ip_src, dst=ip_dst) /\
                              TCP(seq=next_tcp_seq_nr, ack=next_tcp_seq_nr-1, flags=flg, dport=tcp_port) /\
                              Raw(load=prev_payload)
            
            next_tcp_seq_nr += prev_len
            packets_new.append(ether_frame)

            # Reset prev_payload on current
            prev_payload = raw_payload
            prev_len = raw_len

    # Build TCP for remaining prev_payload (if any)
    if prev_len > 0:
        flg = 0x02 if next_tcp_seq_nr == 1 else 0x18   
            
        if ip_ver == 4:          
            ether_frame = Ether(src=src_mac, dst=dst_mac) /\
                          IP(src=ip_src, dst=ip_dst) /\
                          TCP(seq=next_tcp_seq_nr, ack=next_tcp_seq_nr-1, flags=flg, dport=tcp_port) /\
                          Raw(load=prev_payload)

        elif ip_ver == 6:
            ether_frame = Ether(src=src_mac, dst=dst_mac) /\
                          IPv6(src=ip_src, dst=ip_dst) /\
                          TCP(seq=next_tcp_seq_nr, ack=next_tcp_seq_nr-1, flags=flg, dport=tcp_port) /\
                          Raw(load=prev_payload)
        
        next_tcp_seq_nr += prev_len
        packets_new.append(ether_frame)

    return packets_new, next_tcp_seq_nr
