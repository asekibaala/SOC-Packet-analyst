import json
import sys
import os
from scapy.all import rdpcap, TCP, Raw, IP

def parse_smb2_create_request(packet):
    """Parse SMB2 Create Request to extract metadata."""
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        if payload[:4] == b'\\\\xfeSMB':
            command = int.from_bytes(payload[12:14], byteorder='little')
            if command == 0x05:  # SMB2 Create Request
                ip_layer = packet[IP]
                tcp_layer = packet[TCP]
                name_offset = int.from_bytes(payload[52:54], byteorder='little')
                name_length = int.from_bytes(payload[54:56], byteorder='little')
                if name_offset + name_length > len(payload):
                    return None
                file_name = payload[name_offset:name_offset + name_length].decode('utf-16le')
                return {
                    "command": "Create Request",
                    "src_ip": ip_layer.src,
                    "src_port": tcp_layer.sport,
                    "dst_ip": ip_layer.dst,
                    "dst_port": tcp_layer.dport,
                    "timestamp": packet.time,
                    "file_name": file_name
                }
    return None

def main(pcap_file):
    packets = rdpcap(pcap_file)
    smb2_info_list = []

    for packet in packets:
        if packet.haslayer(TCP) and packet.haslayer(IP):
            smb2_info = parse_smb2_create_request(packet)
            if smb2_info:
                smb2_info_list.append(smb2_info)

    output_metadata_file = "smb2_create_requests_metadata.json"
    with open(output_metadata_file, 'w') as f:
        json.dump(smb2_info_list, f, indent=4)
    print(f"SMB2 Create Request information has been saved to {output_metadata_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 detect_smb2_create_requests.py <pcap_file>")
        sys.exit(1)
    pcap_file = sys.argv[1]
    main(pcap_file)
