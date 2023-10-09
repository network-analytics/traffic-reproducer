#
# Copyright(c) 2023 Swisscom (Schweiz) AG
# Authors: Marco Tollini, Leonardo Rodoni
# Distributed under the MIT License (http://opensource.org/licenses/MIT)
#

# External Libraries
from scapy.all import IP, IPv6, TCP, UDP

def filter_generator(flt):
    if flt is None:
        return None

    def F(pkt):
        if 'ip' in flt:
            if IP or IPv6 not in pkt:
                return False
            elif IP in pkt:
              for f in flt['ip']:
                  if not getattr(pkt[IP], f) == flt['ip'][f]:
                      return False
            elif IPv6 in pkt:
              for f in flt['ip']:
                  if not getattr(pkt[IPv6], f) == flt['ip'][f]:
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

        return True
    return F
