# Traffic Reproducer

Given a PCAP and a configuration file, this scapy-based tool can reproduce traffic to a collector. This can be useful, for example, to debug or test a collector with data from some routers or with handcrafted telemetry data.

## Features

- Reproduce IPFIX/NFv9/NFv5, BMP and BGP from pcap files
- Reproduce TCP or UDP payload from pcap files (for well formed pcaps of protocols that don't need special handling or sleeps)
- Simulates respecting the inter-packet timestamps within the PCAP
- Simulates multiple clients via multiple configurable IPs
- Support for VRF in linux
- Easy integration with new protocols
- Provides pcap pre-processing functionality to extract clean IPFIX/BGP/BMP sessions from raw pcap captures (for deterministic repro)

## Installation

You need to run the software with Python 3.7 or newer.

First make sure you have all the submodules pulled:
```
git submodule update --init
```

Then create the virtual environment and use the `requirements.txt` file to install the dependencies.
```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```sh
> python main.py -h
usage: main.py [-h] -t CFG [-v] [-d] [-p] [--no-sync] [--keep-open]

Network Telemetry Traffic Reproducer: reproduce IPFIX/NetFlow, BGP and BMP Traffic based on pcap file.

options:
  -h, --help          show this help message and exit
  -t CFG, --cfg CFG   YAML configuration file path
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
  --ask-for-input     Whether to ask for input before reproducing each pcap file
                        --> default is reproducing right away all pcap files in the config file one after the other
```

### Recording a pcap file

You can use `tcpdump` tool in Linux to record a PCAP. The simplest command is as follows:

```
tcpdump -vvv -w one.pcap
```

This will record from a default interface any packet and will write a PCAP file into `one.pcap`. Thanks to `-vvv` you will see the number of packets captured so far

A more realistic example is as follows:

```
tcpdump -vvv -i vrf300  -n host 10.0.0.1 -w ./two.pcap
```

With `-i vrf300` `tcpdump` listens only to interface named `vrf300`. With `-n host 10.0.0.1` `tcpdump` is going to filter packets coming from or going to IP 10.0.0.1.

### Pcap pre-processing
Pre-processing the pcap file is not mandatory for reproduction. The purpose is to cleanup the pcap files so that they contain clean session and can be reproduced in a deterministic way to a collector (e.g. for test automation).

The following features are supported:
- Extract BMP/BGP/IPFIX sessions from a pcap based on filter parameters (ip, port, ipfix version, bmp msg type, bgp msg type)
- Ensure that only BGP sessions with an OPEN message are included, and also add some delay between BGP OPEN and the rest of the session (since some collectors will need some time to send the response, and since we are faking the BGP handshake we need to give time)
- Ensure that only BMP sessions with an INIT message are included
- Ensure that any IPFIX (data&option) record is discarded if the template is not present
- Replace pcap timestamp starting from a reference (full-minute), with configurable inter-packet-time and inter-protocol-time
- Provides json file with summary of pcap content (protocol session details)
- Provides new pcap and sample config file for reproducing it

Example call (-p flag triggers the pre-processing!):
```
python main.py -d -p --cfg examples/pcap_processing/ipfix-bmp.yml
```

The output files (pcap, config file, json info file) will be added in a new folder (in this case per default examples/pcap_processing/ipfix-bmp/, but this can also be modified as a config parameter).

Have a look at this and some other example in [examples/pcap_processing](./examples/pcap_processing).

## Internals

### Time bucketing

Some collectors will do aggregation at a minute bucketing (e.g. pmacct). In other words, some collectors will accumulate IPFIX data from second 0 to second 59 of each minute, and then will aggregate and send the aggregated data. As such, the position of the IPFIX in the minute is very important (please, refer to the following image to better understand the problem). That is why before sending the first IPFIX message, the reproducer will wait to sync the minute as in the PCAP. This behaviour can be disabled with `--no-sync`.

![](./docs/img/aggregation-explanation.svg)
