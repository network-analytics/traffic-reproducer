#
# Copyright(c) 2023 Swisscom (Schweiz) AG
# Authors: Marco Tollini, Leonardo Rodoni
# Distributed under the MIT License (http://opensource.org/licenses/MIT)
#

# External Libraries
from scapy.all import IP, IPv6, TCP, UDP, raw

def bgp_filter_generator(flt):
    if flt is None:
        return None

    # DEBUG AS NOT WORKING PROPERLY IN ALL CASES.....
    def F(pkt):
        if 'bgp' in flt:
            if TCP not in pkt:
                return False
            for f in flt['bgp']:
                if getattr(BGPHeader(raw(pkt[TCP].payload)), f) not in flt['bgp'][f]:
                    return False

        return True
    return F
