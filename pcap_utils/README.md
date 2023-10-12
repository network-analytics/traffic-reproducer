## Pcap tools:

- tools called by pcap_processing.py (PcapProcessing class), but can also be used as standalone tools

### Description of the tools/scripts:


## IMPORTANT: each script needs to be able to anonymize the traffic...
## --> anonymization which is consistent between all the protocols..
##    --> not so bad: define a random integer in pcap_processing.py passed as an argument
##    --> use the same hash to randomize--> leading to the same ip/mac randomized from the original ip/macs (just don't share the random number and it is fine...)
