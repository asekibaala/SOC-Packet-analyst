import json
import sys
from scapy.all import rdpcap
from scapy.layers.l2 import Ether

def extract_ethernet_info(packet):
    """Extract Ethernet II information from a packet."""
    if packet.haslayer(Ether):
        eth_layer = packet[Ether]
        eth_info = {
            "src": eth_layer.src,
            "dst": eth_layer.dst,
            "type": eth_layer.type
        }
        return eth_info
    return None

def extract_frame1_ethernet(pcap_file):
    packets = rdpcap(pcap_file)
    if len(packets) == 0:
        print("No packets found in the pcap file.")
        return

    frame1 = packets[0]
    eth_info = extract_ethernet_info(frame1)
    
    if eth_info is None:
        print("Frame 1 does not contain Ethernet II information.")
        return

    output_file = "frame1_ethernet_info.json"
    with open(output_file, 'w') as f:
        json.dump(eth_info, f, indent=4)

    print(f"Frame 1 Ethernet II information has been saved to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 extract_ethernet_info.py <pcap_file>")
        sys.exit(1)
    input_file = sys.argv[1]
    extract_frame1_ethernet(input_file)
