import json
import os
import sys
from scapy.all import rdpcap, TCP, UDP, Raw
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

def packet_to_dict(packet):
    """Convert a scapy packet to a dictionary."""
    pkt_dict = {
        "timestamp": str(packet.time),  # Convert timestamp to string
        "layers": []
    }

    if packet.haslayer(Ether):
        ether_layer = packet[Ether]
        pkt_dict["layers"].append({
            "type": "Ethernet",
            "src": ether_layer.src,
            "dst": ether_layer.dst,
            "type_hex": ether_layer.type
        })

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        pkt_dict["layers"].append({
            "type": "IP",
            "src": ip_layer.src,
            "dst": ip_layer.dst,
            "proto": ip_layer.proto,
            "tos": ip_layer.tos,
            "len": ip_layer.len,
            "id": ip_layer.id,
            "ttl": ip_layer.ttl,
            "flags": str(ip_layer.flags),  # Convert flags to string
            "frag": ip_layer.frag,
            "chksum": ip_layer.chksum
        })

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        pkt_dict["layers"].append({
            "type": "TCP",
            "sport": tcp_layer.sport,
            "dport": tcp_layer.dport,
            "seq": tcp_layer.seq,
            "ack": tcp_layer.ack,
            "dataofs": tcp_layer.dataofs,
            "reserved": tcp_layer.reserved,
            "flags": str(tcp_layer.flags),  # Convert flags to string
            "window": tcp_layer.window,
            "chksum": tcp_layer.chksum,
            "urgptr": tcp_layer.urgptr
        })

    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        pkt_dict["layers"].append({
            "type": "UDP",
            "sport": udp_layer.sport,
            "dport": udp_layer.dport,
            "len": udp_layer.len,
            "chksum": udp_layer.chksum
        })

    if packet.haslayer(Raw):
        raw_layer = packet[Raw]
        pkt_dict["layers"].append({
            "type": "Raw",
            "load": raw_layer.load.hex()
        })

    return pkt_dict

def read_pcap(file_path):
    packets = rdpcap(file_path)
    packets_list = []
    for packet in packets:
        pkt_dict = packet_to_dict(packet)
        packets_list.append(pkt_dict)
    return packets_list

def save_to_json(data, output_file):
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=4)

def main(input_file):
    packets_data = read_pcap(input_file)
    output_file = os.path.splitext(input_file)[0] + ".json"
    save_to_json(packets_data, output_file)
    print(f"Data from {input_file} has been saved to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 pcap_to_json.py <pcap_file>")
        sys.exit(1)
    input_file = sys.argv[1]
    main(input_file)
