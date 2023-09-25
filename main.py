# External Libraries
import argparse
import yaml
import signal
import sys
import logging
import pathlib
from ast import arg
from time import time, sleep
from prettytable import PrettyTable
from threading import Thread
from queue import Queue
from scapy.all import IP, IPv6, TCP, UDP, raw, Raw

# Internal Libraries
from filter import filter_generator
from client import Client
from packet_manager import PacketManager, PacketWithMetadata
from report import report
from proto import Proto

def parse_args():
    parser = argparse.ArgumentParser(
        prog="Network Telemetry Traffic Reproducer",
        description="Reproduce IPFIX/NetFlow, BGP and BMP Traffic based on pcap file.",
        epilog="-----------------------")

    parser.add_argument(
        "-t", "--test",
        type=pathlib.Path,
        dest='cfg',
        required=True,
        help="Test YAML configuration file specifying repro and collector IPs and other reproduction parameters (see examples folder).",
    )

    parser.add_argument(
        '-v', '--verbose',
        help="Set log level to INFO [default=WARNING unless -d/--debug flag is used].",
        action="store_const",
        dest="loglevel",
        const=logging.INFO,
        default=logging.WARNING,
    )

    parser.add_argument(
        '-d', '--debug',
        help="Set log level to DEBUG [default=WARNING unless -v/--verbose flag is used].",
        action="store_const",
        dest="loglevel",
        const=logging.DEBUG,
    )

    parser.add_argument(
        '--no-sync',
        help="Disable IPFIX bucket sync (start reproducing pcap right away without waiting the next full minute and without considering pcap timestamps?).",
        action="store_const",
        dest="nosync",
        const=True,
        default=False,
    )

    parser.add_argument(
        '--keep-open',
        help="Do not close the TCP connection when finished replaying pcap [default=False]",
        action="store_const",
        dest="keep_open",
        const=True,
        default=False,
    )

    args = parser.parse_args()
    return args

def parse_config_file(cfg):
    with open(cfg, "r") as stream:
        return yaml.safe_load(stream)

# create src_ip -> repro_ip mapping
def create_ip_map(network_map):
    table = PrettyTable(['src_ip', 'repro_ip'])

    ip_map = {}
    for m in network_map:
        ip_map[m['src_ip']] = m
        table.add_row([m['src_ip'], m['repro_ip']])

    logging.info(table)
    return ip_map

def sleep_between_pkts(packet, real_start_time, pcap_start_time, time_factor):
    pcap_this_time = packet.time
    curr_time = time()
    ellapsed_real_time = curr_time - real_start_time
    ellapsed_pcap_time = float(pcap_this_time - pcap_start_time)
    theoretical_sleep_time = ellapsed_pcap_time * time_factor - ellapsed_real_time
    report.set_delay(min(theoretical_sleep_time, 0))

    sleep_time = max(theoretical_sleep_time - 0.01, 0)
    logging.debug(f"Sleeping {sleep_time} - Ellapsed real time: {ellapsed_real_time} (after sleep {ellapsed_real_time + sleep_time}) - Ellapsed pcap time: {ellapsed_pcap_time}")
    return sleep_time


def main():
    # parse arguments
    args = parse_args()

    logging.basicConfig(level=args.loglevel)

    # parse test config file
    config = parse_config_file(args.cfg)

    # check if we want multithreading enabled
    is_threading = config['optimize']['threading']

    # gather list of supported protocol from Proto class
    supported_protos = [e.value for e in Proto]

    # create src_ip -> repro_ip mapping (IP map)
    ip_map = create_ip_map(config['network']['map'])

    # protocol selectors
    selectors = {proto: filter_generator(config[proto]['select']) for proto in supported_protos if proto in config}

    # map of clients
    clients = {}

    def stop_application(sig=None, frameg=None):
        if is_threading:
            logging.info("Shutting threading clients")
            for client in clients:
                queue = clients[client]['queue']
                queue.put(None)
            for client in clients:
                th = clients[client]['thread']
                th.join()

        if not is_threading:
            for client in clients:
                pclients = clients[client].pclients
                for pclient in pclients:
                    pc = pclients[pclient]
                    pc.should_run = False
                for pclient in pclients:
                    pc = pclients[pclient]
                    pc.receiving_thread.join()


        if report.is_alive():
            logging.info("Shutting down report thread")
            report.stop()
            report.join()
            logging.info("Printing last statistics")
            report.print_stats()

        sys.exit(0)

    signal.signal(signal.SIGINT, stop_application)

    # start reporting
    report.start_thread()

    # pcap timestamp for first packet sent
    pcap_start_time = None
    # real timestamp for first packet sent
    real_start_time = None

    # read pcap file and select packets according to selectors
    pm = PacketManager(
        pcap_path=config['pcap'],
        selectors=selectors,
        preload=config['optimize']['preload']
    )

    packetwm: PacketWithMetadata
    for packetwm in pm:
        packet = packetwm.packet
        i = packetwm.number

        try:
            logging.debug(f"[{i}] start packet analysis")

            if IP in packet:
                ip_src = packet[IP].src
            elif IPv6 in packet:
                ip_src = packet[IPv6].src

            logging.debug(f"[{i}] has ip_src: {ip_src}")

            if ip_src not in ip_map:
                report.pkt_nopeer_countup()
                logging.debug(f"[{i}] discarded as {ip_src} not in IP Map (not specified as src_ip in config file)")
                continue

            if ip_src not in clients:
                network_map = ip_map[ip_src]
                collectors = {x: config[x]['collector'] for x in supported_protos if x in config}
                optimize_network = config['optimize']['network']
                network_interface = config['network']['interface']

                queue_th = Queue() if is_threading else None
                client = Client(
                    queue_th=queue_th,
                    network_map=network_map,
                    collectors=collectors,
                    optimize_network=optimize_network,
                    network_interface=network_interface,
                )

                if is_threading:
                    client_th = Thread(target=client.listen)
                    client_th.start()

                    clients[ip_src] = {
                        'thread': client_th,
                        'queue': queue_th,
                    }
                else:
                    clients[ip_src] = client

            # calculate sleep time and sleep
            if pcap_start_time is not None:
                sleep_time = sleep_between_pkts(packet, real_start_time, pcap_start_time, config['time_factor'])
                report.set_sleep(sleep_time)
                if sleep_time > 10:
                    logging.info(f"Sleeping for {sleep_time}s")
                sleep(sleep_time)


            # the reproduce function actually decide if it should sync ipfix or not
            should_sync_ipfix = pcap_start_time is None and not args.nosync

            # return 0 signifies that packet was not discared but program in multithreading
            sent = clients[ip_src].reproduce(packetwm, should_sync_ipfix=should_sync_ipfix)

            if pcap_start_time is None and sent >= 0:
                pcap_start_time = packet.time
                real_start_time = time()
                report.set_start_time(real_start_time)

            if is_threading:
                for ip_src in clients:
                    th = clients[ip_src]['thread']
                    if not th.is_alive():
                        raise Exception(f"Thread for {ip_src} is dead!")
        except Exception as e:
            logging.critical(f"Error! Stopping application on packet [{i}]: {e}")
            break

    if not (args.keep_open or config['keep_open']):
        print('Closing sockets and stopping application...')
        stop_application()

if __name__ == "__main__":
    main()
