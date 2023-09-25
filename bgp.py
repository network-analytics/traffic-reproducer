# External Libraries
import ipaddress
from scapy.all import TCP, raw

def is_bgp_open_message(payload, original_bgp_id):
    if len(payload) <= 28:
        # packet too short
        return False

    if  not payload[18] == 1:
        # packet type is not 1 (OPEN)
        return False

    pcap_bgp_id = str(ipaddress.ip_address(int.from_bytes(payload[24:28], 'big', signed=False)))
    if original_bgp_id != pcap_bgp_id:
        # packet BGP ID is not as expected! Possibly packet was not a complete BGP packet
        return False

    return True
