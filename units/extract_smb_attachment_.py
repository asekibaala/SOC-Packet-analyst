import os
import json
import sys
from scapy.all import rdpcap, TCP, Raw, IP

folder_name = 'extracted_files'
if not os.path.exists(folder_name):
    os.mkdir(folder_name)

def parse_smb2_header(payload):
    if len(payload) < 64:
        return None, None
    protocol_id = payload[:4]
    if protocol_id != b'\xfeSMB':
        return None, None
    command = int.from_bytes(payload[12:14], byteorder='little')
    return command, payload

def extract_smb_info(packet):
    smb_info = {}
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load
        command, smb_payload = parse_smb2_header(payload)
        if command in [0x05, 0x08, 0x09]:  # Create, Read, Write
            ip_layer = packet[IP]
            tcp_layer = packet[TCP]
            smb_info = {
                "command": command,
                "src_ip": ip_layer.src,
                "src_port": tcp_layer.sport,
                "dst_ip": ip_layer.dst,
                "dst_port": tcp_layer.dport,
                "timestamp": packet.time,
                "data": smb_payload
            }
            if command == 0x05:  # Create
                name_offset = int.from_bytes(smb_payload[52:54], byteorder='little')
                name_length = int.from_bytes(smb_payload[54:56], byteorder='little')
                if name_offset + name_length <= len(smb_payload):
                    smb_info["file_name"] = smb_payload[name_offset:name_offset + name_length].decode('utf-16le')
            elif command == 0x09:  # Write
                smb_info["file_data"] = smb_payload[64:]
            elif command == 0x08:  # Read
                smb_info["file_data"] = smb_payload[64:]
    return smb_info

def save_file(data, file_path):
    with open(file_path, 'wb') as f:
        f.write(data)

def main(pcap_file):
    scapy_cap = rdpcap(pcap_file)
    attachments_info = []
    for packet in scapy_cap:
        smb_info = extract_smb_info(packet)
        if smb_info:
            file_name = smb_info.get("file_name", f"file_from_packet_{int(smb_info['timestamp'])}.dat")
            file_path = os.path.join(folder_name, file_name)
            if "file_data" in smb_info:
                save_file(smb_info["file_data"], file_path)
            if 'file_data' in smb_info:
                file_size = len(smb_info['file_data'])
            else:
                file_size = 0
            file_metadata = {
                "file_name": file_name,
                "file_size": file_size,
                "src_ip": smb_info["src_ip"],
                "src_port": smb_info["src_port"],
                "dst_ip": smb_info["dst_ip"],
                "dst_port": smb_info["dst_port"],
                "timestamp": smb_info["timestamp"]
            }
            attachments_info.append(file_metadata)
    output_metadata_file = os.path.join(folder_name, "metadata.json")
    with open(output_metadata_file, 'w') as f:
        json.dump(attachments_info, f, indent=4)
    print(f"SMB information has been saved to {output_metadata_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 extract_smb_attachments.py <pcap_file>")
        sys.exit(1)
    pcap_file = sys.argv[1]
    main(pcap_file)