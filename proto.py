#
# Copyright(c) 2023 Swisscom (Schweiz) AG
# Authors: Marco Tollini, Leonardo Rodoni
# Distributed under the MIT License (http://opensource.org/licenses/MIT)
#

# External Libraries
from enum import Enum

class Proto(Enum):
    bgp = 'bgp'
    bmp = 'bmp'
    ipfix = 'ipfix'
