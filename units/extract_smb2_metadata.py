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

def extract_smb2_info(packet):
    smb2_info = {}
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load
        command, smb_payload = parse_smb2_header(payload)
        if command is not None:  # SMB2 Command detected
            ip_layer = packet[IP]
            tcp_layer = packet[TCP]
            smb2_info = {
                "command": command,
                "src_ip": ip_layer.src,
                "src_port": tcp_layer.sport,
                "dst_ip": ip_layer.dst,
                "dst_port": tcp_layer.dport,
                "timestamp": packet.time,
                "data": payload.hex()  # Store the payload as hex for reference
            }
            if command == 0x05:  # Create Request
                name_offset = int.from_bytes(smb_payload[52:54], byteorder='little')
                name_length = int.from_bytes(smb_payload[54:56], byteorder='little')
                if name_offset + name_length <= len(smb_payload):
                    smb2_info["file_name"] = smb_payload[name_offset:name_offset + name_length].decode('utf-16le')
            elif command == 0x09:  # Write Request
                smb2_info["file_data"] = smb_payload[64:]
            elif command == 0x08:  # Read Request
                smb2_info["file_data"] = smb_payload[64:]
    return smb2_info

def main(pcap_file):
    scapy_cap = rdpcap(pcap_file)
    smb2_info_list = []

    for packet in scapy_cap:
        smb2_info = extract_smb2_info(packet)
        if smb2_info:
            smb2_info_list.append(smb2_info)

    output_metadata_file = "smb2_metadata.json"
    with open(output_metadata_file, 'w') as f:
        json.dump(smb2_info_list, f, indent=4)
    print(f"SMB2 information has been saved to {output_metadata_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 extract_smb2_metadata.py <pcap_file>")
        sys.exit(1)
    pcap_file = sys.argv[1]
    main(pcap_file)
