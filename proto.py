#
# Copyright(c) 2023 Swisscom (Schweiz) AG
# Authors: Marco Tollini, Leonardo Rodoni
# Distributed under the MIT License (http://opensource.org/licenses/MIT)
#

# External Libraries
from enum import Enum

class Proto(Enum):
    ipfix = 'ipfix'
    bmp = 'bmp'
    bgp = 'bgp'
    udp_generic = 'udp_generic'
    tcp_generic = 'tcp_generic'
