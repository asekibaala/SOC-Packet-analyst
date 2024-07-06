import json
import os
import sys
from scapy.all import rdpcap, TCP, Raw
from scapy.layers.inet import IP

def packet_to_dict(packet):
    """Convert a scapy packet to a dictionary, focusing on SMB-related layers."""
    pkt_dict = {
        "timestamp": str(packet.time),  # Convert timestamp to string
        "layers": []
    }

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

    if packet.haslayer(Raw):
        raw_layer = packet[Raw]
        payload = raw_layer.load
        if payload.startswith(b"\xffSMB") or payload.startswith(b"\xfeSMB"):
            pkt_dict["layers"].append({
                "type": "SMB",
                "data": payload.hex()
            })

    return pkt_dict

def read_pcap(file_path):
    packets = rdpcap(file_path)
    smb_packets_list = []
    for packet in packets:
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            if payload.startswith(b"\xffSMB") or payload.startswith(b"\xfeSMB"):  # Filter SMB and SMB2 packets
                pkt_dict = packet_to_dict(packet)
                smb_packets_list.append(pkt_dict)
    return smb_packets_list

def save_to_json(data, output_file):
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=4)

def main(input_file):
    smb_packets_data = read_pcap(input_file)
    if smb_packets_data:
        output_file = os.path.splitext(input_file)[0] + "_smb.json"
        save_to_json(smb_packets_data, output_file)
        print(f"SMB data from {input_file} has been saved to {output_file}")
    else:
        print(f"No SMB data found in {input_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 extract_smb_to_json.py <pcap_file>")
        sys.exit(1)
    input_file = sys.argv[1]
    main(input_file)
