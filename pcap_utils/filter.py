#
# Copyright(c) 2023 Swisscom (Schweiz) AG
# Authors: Marco Tollini, Leonardo Rodoni
# Distributed under the MIT License (http://opensource.org/licenses/MIT)
#

# External Libraries
from scapy.all import IP, IPv6, TCP, UDP, raw
from scapy.layers.netflow import NetflowHeader
from scapy.contrib.bgp import *

def filter_generator(flt):
    if flt is None:
        return None

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

        if 'cflow' in flt:
            if UDP not in pkt:
                return False
            for f in flt['cflow']:
                if getattr(NetflowHeader(raw(pkt[UDP].payload)), f) not in flt['cflow'][f]:
                    return False

        if 'bgp' in flt:
            if TCP not in pkt:
                return False
            if IP not in pkt and IPv6 not in pkt:
                return False
            elif IP in pkt:
                #print("tcp payload len: ", pkt[IP].len - 4*pkt[IP].ihl - 4*pkt[TCP].dataofs)
                # too small, hence discard --> TODO: move this filtering somewhere else since we need to execute it all the time
                #   and not only when bgp is defined in the selectors!!!!!
                if pkt[IP].len - 4*pkt[IP].ihl - 4*pkt[TCP].dataofs < 19: 
                    return False
            elif IPv6 in pkt:
                if pkt[IPv6].plen - 4*pkt[TCP].dataofs < 19: # too small
                    return False
            # TODO: also check if payload contains BGP marker ffff, otherwise discard! (don't know if strictly needed?)
            #    --> this put somewhere else as well
            #    --> this is important since sometimes we can have crap stuff...

        return True
    return F

# Additional BGP specific filters
#  --> can be applied only for defragmented BGP sessions!
def bgp_msg_filter_generator(flt):
    if flt is None:
        return None

    def F(pkt):
        if 'bgp' in flt:
          
            for f in flt['bgp']:
                if getattr(BGPHeader(raw(pkt)), f) not in flt['bgp'][f]:
                    return False

        return True
    return F
