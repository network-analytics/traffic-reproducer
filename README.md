# Traffic Reproducer

Given a PCAP and a configuration file, this scapy-based tool can reproduce traffic to a collector. This can be useful, for example, to debug or test a collector with a recording from some routers.

## Features

- Reproduce IPFIX/NFv9/NFv5, BMP and BGP from pcap files
- Simulates respecting the timestamps within the PCAP
- Simulates multiple clients via multiple configurable IPs
- Support for VRF in linux
- Easy integration with new protocols
- [In Development] Tools for generating and processing pcap files so that they're ready to be reproduces

## Installation

You need to run the software with Python 3.7 or newer. We suggest to create a virtual environment and use the `requirements.txt` file to install the correct packages
```
python3 -m venv venv
source venv/bin/activate
pip install -r requiremements.txt
```

### Pcap file record and preprocessing

TODO: write this section 

### Run the program

```sh
> python main.py -h
usage: main.py [-h] -t CFG [-v] [-d] [--no-sync] [--keep-open]

Network Telemetry Traffic Reproducer: reproduce IPFIX/NetFlow, BGP and BMP Traffic based on pcap file.

options:
  -h, --help          show this help message and exit
  -t CFG, --test CFG  Test YAML configuration file path specifying repro and collector IPs and other reproduction parameters (see examples folder).
  -v, --verbose       Set log level to INFO [default=WARNING unless -d/--debug flag is used].
  -d, --debug         Set log level to DEBUG [default=WARNING unless -v/--verbose flag is used].
  --no-sync           Disable IPFIX bucket sync (start reproducing pcap right away without waiting the next full minute).
  --keep-open         Do not close the TCP connection when finished replaying pcap [default=False].

-----------------------
```

### Time bucketing

Some collectors will do aggregation at a minute bucketing (e.g. pmacct). In other words, some collectors will accumulate IPFIX data from second 0 to second 59 of each minute, and then will aggregate and send the aggregated data. As such, the position of the IPFIX in the minute is very important (please, refer to the following image to better understand the problem). That is why before sending the first IPFIX message, the reproducer will wait to sync the minute as in the PCAP. This behaviour can be disabled with `--no-sync`.

![](./docs/img/aggregation-explanation.svg)
