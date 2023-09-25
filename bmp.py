# External Libraries
import ipaddress
from scapy.all import TCP, raw

from bgp import is_bgp_open_message

def is_bmp_open_message(payload, original_bgp_id):
    if len(payload) <= 68:
        # packet too short
        return False

    msg_type = payload[5]
    if msg_type != 3:
        # not peer up
        return False

    # BMP Peer UP has first the sent PDU, then the received
    two_bgp_open = payload[68:]

    return is_bgp_open_message(two_bgp_open, original_bgp_id)
