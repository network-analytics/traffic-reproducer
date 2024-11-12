from scapy.all import rdpcap, wrpcap
import sys
import os

def merge_pcaps(pcap_list, output_file):
        """
        Merges multiple PCAP files into a single PCAP file.

        :param pcap_list: List of paths to the PCAP files to be merged
        :param output_file: Path to the output PCAP file
        """
        merged_packets = []
        for pcap in pcap_list:
                packets = rdpcap(pcap)
                merged_packets.extend(packets)

        wrpcap(output_file, merged_packets)

# Example usage:
# pcap_files = ['file1.pcap', 'file2.pcap', 'file3.pcap']
# merge_pcaps(pcap_files, 'merged_output.pcap')

if __name__ == "__main__":

        if len(sys.argv) < 3:
                print("Usage: python pcap_merger.py <output_file> <pcap_file1> <pcap_file2> ...")
                sys.exit(1)

        output_file = sys.argv[1]
        pcap_files = sys.argv[2:]

        # Adjust paths if running from an arbitrary directory
        pcap_files = [os.path.abspath(pcap) for pcap in pcap_files]

        merge_pcaps(pcap_files, output_file)
