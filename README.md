# Traffic Reproducer

Given a PCAP and a configuration file, this scapy-based tool can reproduce traffic to a collector. This can be useful, for example, to debug or test a collector with data from some routers or with handcrafted telemetry data.

## Features

- Reproduce IPFIX/NFv9/NFv5, BMP and BGP from pcap files
- Simulates respecting the inter-packet timestamps within the PCAP
- Simulates multiple clients via multiple configurable IPs
- Support for VRF in linux
- Easy integration with new protocols
- Extract clean IPFIX/BGP/BMP sessions from raw pcap captures before reproducing
- Provide json summary of pcap content (protocol session details)
- [Vision] Packet generators for new protocols

## Installation

You need to run the software with Python 3.7 or newer. We suggest to create a virtual environment and use the `requirements.txt` file to install the correct packages
```
python3 -m venv venv
source venv/bin/activate
pip install -r requiremements.txt
```

## Usage

```sh
> python main.py -h
usage: main.py [-h] -t CFG [-v] [-d] [-p] [--no-sync] [--keep-open]

Network Telemetry Traffic Reproducer: reproduce IPFIX/NetFlow, BGP and BMP Traffic based on pcap file.

options:
  -h, --help          show this help message and exit
  -t CFG, --test CFG  YAML configuration file path
                        --> set IPs and other parameters for reproduction, look at examples folder for some sample configs
  -v, --verbose       Set log level to INFO
                        --> default log level is WARNING, unless -d/--debug flag is used
  -d, --debug         Set log level to DEBUG
                        --> default log level is WARNING, unless -v/--verbose flag is used
  -p, --pcap-proc     Enable pcap pre-processing before reproducing
                        --> can also be used as standalone feature (pre-process and produce output pcap without reproducing)
                        --> requires pcap_processing entry in the config file, look at examples folder for some sample configs
  --no-sync           Disable IPFIX bucket synchronization to the next full minute
                        --> also configurable through the config file [args OR config]
  --keep-open         Keep the TCP connections open when finishing the pcap reproduction
                        --> also configurable through the config file [args OR config]

-----------------------
```

## Generating a pcap file

### Pcap pre-processing

TODO: explain how to use and what it does 

## Internals

### Time bucketing

Some collectors will do aggregation at a minute bucketing (e.g. pmacct). In other words, some collectors will accumulate IPFIX data from second 0 to second 59 of each minute, and then will aggregate and send the aggregated data. As such, the position of the IPFIX in the minute is very important (please, refer to the following image to better understand the problem). That is why before sending the first IPFIX message, the reproducer will wait to sync the minute as in the PCAP. This behaviour can be disabled with `--no-sync`.

![](./docs/img/aggregation-explanation.svg)
