# Tools

## pre-processing

Question: should it be part of the main traffic repro code? --> no, separate script [maybe in the future it could be callable from the repro file and then be executed
               and after processing the retro would be automatically started using the files (or stuff in memory...)]

Idea: feed in a capture from a router, specify wanted protocols in a config file, then the script will prepare output for handling

Idea: ideally we feed a random capture pcap here (even without specifying any ips or arguments, see example 2 with basic config) 
       --> and this tool creates set of files ready to be reproduced/to be used for a test case
          [traffic-00.pcap, traffic-reproducer-00.yml, traffic-info.json]

Protocol packets are adjusted in position according to protocols: list below (e.g. proto1 packets sent befor all proto2 packets, etc..)

Also for supported protocols there is a custom handling (e.g. discard packets before template, discard all bgp before open, add wait times...)  
For non-supported/unknown ones --> simply keep all the packets as they are (only move the order according to config)

-> for each proto1, proto2, etc.. mandatory is name (can be unknown or something not supported, but still mandatory), and dst_port (which is the actual proto-recognizer)

-> for supported proto, there might be custom config flags (see below e.g. for ipfix)
  --> this is where we would add any protocol field modification, should some be required...


-> dst ip of all packets automatically set to 0.0.0.0 [anyway we don't care since the reproducer will ignore it...]

-> for ipfix, bmp, bgp support anonymization

-> idea: could even have multiple pcaps as input, simply to first merge before processing everyting....

EXECUTION: this we might need to think about if we ever need to pass big pcaps through this script
         --> pass all the pcap per each proto1, proto2, proto3

Example 1: config file yml:                    
______

intput-pcap-file:  example_capture_from_router.pcap

output-repro-file:  traffic-reproducer-00.yml                           # also provide a config file for the traffic-reproducer that can be directly used for reproduction (with default setting)!
output-pcap-file:   traffic-00.pcap 
output-report:      traffic-info.json                                   # some information about the pcap (bgp sessions, bmp sessions, router ips, start-end time, number of packets, size, etc...)
                                                                          --> since we anyway need to keep state for e.g. bgp sessions (to know if we received OPEN before or not)
                                                                          --> e.g. bgp session from router X.x.x.x with OPEN at XX:05 and last packet at XX:10

protocols:
  - name: [bgp, bmp, ipfix, other/non-supported]                        # here if name matches a supported proto -> do custom handling 
    dst_port: 
    dst_port_new:                                                       # by default (if empty or not provided) -> set to default protocol port (if protocol known)
    src_ip:
    src_ip_new:                                                         # by default (if empty or not provided) -> do not change
    packet-intervals: 1ms                                               # default 1ms, exept after the bgp open or bmp open message (otherwise pmacct crashes / does not work correctly if receives second packet before answering)

  proto2:
    name:     bgp
    dst_port: 179
    src_ip:   10.235.1.3
    src_ip_new: 172.10.100.1
    

  proto3:
    name:     bgp
    dst_port: 179
    src_ip:   10.235.1.5

  proto4
    name:     bmp
    dst_por:  1790
    src_ip:   *                 # * or argument not provided: consider all IPs that are sending bmp!
    stats: no                   # discard bmp stats (only care about route monitor with updates e.g.)

  proto5:
    name:     ipfix
    dst_port: 9991
    src_ip:   10.201.1.3
    custom:
      ipfix_version: [v9, v10]    # with this config, any v5 would be discarded
      repeated_templates: no      # default yes, and it means keep all templates even if they were seen before...
      anonymize: yes              # default no, if yes=change all in-protocol IPs/MAC_addresses to random ones (use some random ips and mac addresses)
      repeat:
        amount: 5                 # add the same packets again 5x times
        sleep: 60                 # every time adding 60s to the timestamps before sending them again
        mixup: yes                # apart from template, mix up the order of the packets
        randomize_counts: yes     # for the repetitions, randomize some of the fields like count, bytes [s.t. subsequent runs are not 100% the same]






BEHAVIOUR PER PROTOCOL:

ALL protos: fix sequence numbers, checksums etc... (this will be automatically fixed by adding new tcp/udp headers)
            -> Time start at XX:05 
            -> interval default 1ms (apart during bgp open handshake)

BGP:
 -> discard anything before open relative to the IP we are considering
    then anything after the open, keep

BMP:
 -> discard anything before init+open messages
 -> option to keep stats or not




 Example 2: most basic config file yml for e.g. bgp + ipfix case:
______

intput-pcap-file:   example_capture_from_router.pcap

output-repro-file:  traffic-reproducer-00.yml 
output-pcap-file:   traffic-00.pcap 
output-report:      traffic-info.json 

protocols:
  proto1:
    name:     bgp
    dst_port: 179
    
  proto2:
    name:     ipfix
    dst_port: 9991


-> here takes bgp from all sources and ipfix from all sources and prepares output pcap cleaning up / preprocessing using all default configs...

                 