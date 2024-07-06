import os
import json
import sys
from scapy.all import rdpcap, TCP, Raw, IP

def parse_smb2_header(payload):
    if len(payload) < 64:
        return None, None
    
    protocol_id = payload[:4]
    if protocol_id != b'\xfeSMB':
        return None, None
    
    command = int.from_bytes(payload[12:14], byteorder='little')
    return command, payload

def check_smb_write_requests_and_responses(pcap_file, output_file):
    packets = rdpcap(pcap_file)
    smb_info_list = []

    for packet in packets:
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = packet[Raw].load
            command, smb_payload = parse_smb2_header(payload)
            if command in [0x09, 0x10]:  # SMB2 Write Request or Response
                smb_info = {
                    "command": "Write Request" if command == 0x09 else "Write Response",
                    "src_ip": packet[IP].src,
                    "src_port": packet[TCP].sport,
                    "dst_ip": packet[IP].dst,
                    "dst_port": packet[TCP].dport,
                    "timestamp": packet.time,
                    "data": payload.hex()
                }
                smb_info_list.append(smb_info)

    with open(output_file, 'w') as f:
        json.dump(smb_info_list, f, indent=4)

    print(f"SMB Write Requests and Responses have been saved to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 check_smb_write_requests_and_responses.py <pcap_file> <output_file>")
        sys.exit(1)
    pcap_file = sys.argv[1]
    output_file = sys.argv[2]
    check_smb_write_requests_and_responses(pcap_file, output_file)
