#
# Copyright(c) 2023 Swisscom (Schweiz) AG
# Authors: Marco Tollini, Leonardo Rodoni
# Distributed under the MIT License (http://opensource.org/licenses/MIT)
#

# External Libraries
import queue
import logging
from threading import Thread, Event
from time import sleep, time
from prettytable import PrettyTable

# Internal Libraries
from proto import Proto

class Report:
    def __init__(self) -> None:
        self.real_start_time = None

        # sent messages per proto
        self.supported_protos = [e.value for e in Proto]
        self.proto_counter = {}
        for proto in self.supported_protos:
            self.proto_counter[proto] = {
                'sent': 0,
                'filtered': 0,
            }

        # pkt with unknown protocol or peer (from configs)
        self.pkt_noproto = 0
        self.pkt_nopeer = 0

        # current delay respect the pcap (no if multithreading)
        self.delay = 0
        self.running_avg_delay = 0
        # only if multithreaded
        self.queue_size = 0
        self.running_avg_queue_size = 0

        self.sleep = 0
        self.running_avg_sleep = 0

        self.stop_signal = Event()
        self._th = Thread(target=self.start)

    def set_start_time(self, start_time):
        self.real_start_time = start_time

    def set_delay(self, delay):
        self.delay = delay
        self.running_avg_delay = 0.3*self.running_avg_delay + 0.7*delay

    def set_queue_size(self, queue_size):
        self.queue_size = queue_size
        self.running_avg_queue_size = 0.3*self.running_avg_queue_size + 0.7*queue_size

    def set_sleep(self, sleep):
        self.sleep = sleep
        self.running_avg_sleep = 0.3*self.running_avg_sleep + 0.7*sleep

    def pkt_proto_sent_countup(self, proto):
        self.proto_counter[proto]['sent'] += 1

    def pkt_proto_filtered_countup(self, proto):
        self.proto_counter[proto]['filtered'] += 1

    def pkt_noproto_countup(self):
        self.pkt_noproto += 1

    def pkt_nopeer_countup(self):
        self.pkt_nopeer += 1

    def print_stats(self):
        logging.info("####################")
        if self.real_start_time is not None:
            curr_time = time()
            logging.info(f'Ellapsed time: {round(curr_time - self.real_start_time, 3)}s')

        table = PrettyTable([
            'metric',
            *self.supported_protos,
            'unknown peer',
            'unknown proto',
        ])
        table.add_row([
            'Packet sent',
            *[self.proto_counter[proto]['sent'] for proto in self.supported_protos],
            '--',
            '--',
        ])
        table.add_row([
            'Packet filtered',
            *[self.proto_counter[proto]['filtered'] for proto in self.supported_protos],
            self.pkt_nopeer,
            self.pkt_noproto,
        ])
        logging.info(table)

        logging.info(f'Delay:\t[Current: {round(self.delay, 3)}s   ][Running average: {round(self.running_avg_delay, 3)}s]')
        logging.info(f'Queue size:\t[Current: {round(self.queue_size, 3)} pkt][Running average: {round(self.running_avg_queue_size, 3)} pkt]')
        logging.info(f'Sleep:\t[Current: {round(self.sleep, 3)}s   ][Running average: {round(self.running_avg_sleep, 3)}s]')

        if self.delay < -1:
            logging.warning(f'Too slow! Current delay: {round(self.delay, 3)}s')
        logging.info("====================")

    def start(self):
        i = 0
        while not self.stop_signal.wait(0):
            if i % 4 == 0:
                self.print_stats()
            sleep(0.5)
            i += 1
        logging.info('Reporter exited')

    def stop(self):
        self.stop_signal.set()

    def join(self):
        self._th.join()

    def start_thread(self):
        self._th.start()

    def is_alive(self):
        return self._th.is_alive()

report = Report()
