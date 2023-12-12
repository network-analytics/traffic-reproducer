#
# Copyright(c) 2023 Swisscom (Schweiz) AG
# Authors: Marco Tollini, Leonardo Rodoni
# Distributed under the MIT License (http://opensource.org/licenses/MIT)
#

# External Libraries
from scapy.all import IP, IPv6, TCP, UDP, raw
from scapy.layers.netflow import NetflowHeader
from scapy.contrib.bgp import BGP, BGPHeader
from pcap_utils.bmp_scapy.bmp import BMP, BMPHeader

def filter_generator(flt):
    if flt is None:
        return None

    def T(pkt):
        return True

    if flt is False:
        return T

    def F(pkt):
        if 'ip' in flt:
            if IP not in pkt and IPv6 not in pkt:
                return False
            elif IP in pkt:
              for f in flt['ip']:
                  if getattr(pkt[IP], f) not in flt['ip'][f]:
                      return False
            elif IPv6 in pkt:
              for f in flt['ip']:
                  if getattr(pkt[IPv6], f) not in flt['ip'][f]:
                      return False

        if 'tcp' in flt:
            if TCP not in pkt:
                return False
            for f in flt['tcp']:
                if not getattr(pkt[TCP], f) == flt['tcp'][f]:
                    return False

        if 'udp' in flt:
            if UDP not in pkt:
                return False
            for f in flt['udp']:
                if not getattr(pkt[UDP], f) == flt['udp'][f]:
                    return False

        if 'ipfix' in flt: # TODO: add to separate filter function as well (then change in the yml from selector to advanced_filter#working only after defrag!) (or select_advanced maybe better naming)
            if UDP not in pkt:
                return False
            for f in flt['ipfix']:
                if getattr(NetflowHeader(raw(pkt[UDP].payload)), f) not in flt['ipfix'][f]:
                    return False

        return True
    return F

# Additional BGP specific filters
#  --> can be applied only for defragmented BGP messages!
def bgp_msg_filter_generator(flt):
    if flt is None:
        return None

    def F(pkt):
        if 'bgp' in flt:
          
            for f in flt['bgp']:
                if getattr(BGP(raw(pkt)), f) not in flt['bgp'][f]:
                    return False

        return True
    return F

# Additional BMP specific filters
#  --> can be applied only on defragmented BMP messages!
def bmp_msg_filter_generator(flt):
    if flt is None:
        return None

    def F(pkt):
        if 'bmp' in flt:
          
            for f in flt['bmp']:
                if getattr(BMP(raw(pkt)), f) not in flt['bmp'][f]:
                    return False

        return True
    return F
