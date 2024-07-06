import os
import json
import sys
from scapy.all import rdpcap, TCP, Raw, IP

SMB2_WRITE_REQUEST = 0x0009
SMB2_WRITE_RESPONSE = 0x0009
SMB2_READ_REQUEST = 0x0008
SMB2_READ_RESPONSE = 0x0008

def parse_smb2_header(payload):
    if len(payload) < 64:  # Ensure the packet is at least as large as the SMB2 header
        return None
    protocol_id = payload[:4]
    if protocol_id != b"\xfeSMB":
        return None
    command = int.from_bytes(payload[12:14], byteorder='little')
    return command

def extract_smb_info(packet):
    """Extract SMB information from a packet."""
    smb_info = {}
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load
        command = parse_smb2_header(payload)
        if command in [SMB2_WRITE_REQUEST, SMB2_READ_REQUEST, SMB2_WRITE_RESPONSE, SMB2_READ_RESPONSE]:
            ip_layer = packet[IP]
            tcp_layer = packet[TCP]
            smb_info = {
                "src_ip": ip_layer.src,
                "src_port": tcp_layer.sport,
                "dst_ip": ip_layer.dst,
                "dst_port": tcp_layer.dport,
                "timestamp": packet.time,
                "data": payload
            }
    return smb_info

def save_file(data, file_path):
    with open(file_path, 'wb') as f:
        f.write(data)

def main(pcap_file):
    scapy_cap = rdpcap(pcap_file)
    attachments_info = []
    output_folder = "extracted_files"

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    for packet in scapy_cap:
        smb_info = extract_smb_info(packet)
        if smb_info:
            # Generate a filename based on metadata and timestamp
            file_name = f"{smb_info['src_ip']}_{smb_info['dst_ip']}_{int(smb_info['timestamp'])}.dat"
            file_path = os.path.join(output_folder, file_name)
            save_file(smb_info['data'], file_path)
            
            file_metadata = {
                "file_name": file_name,
                "file_size": len(smb_info['data']),
                "src_ip": smb_info['src_ip'],
                "src_port": smb_info['src_port'],
                "dst_ip": smb_info['dst_ip'],
                "dst_port": smb_info['dst_port'],
                "timestamp": smb_info['timestamp']
            }
            attachments_info.append(file_metadata)

    output_metadata_file = os.path.join(output_folder, "metadata.json")
    with open(output_metadata_file, 'w') as f:
        json.dump(attachments_info, f, indent=4)

    print(f"Extracted files and metadata have been saved to {output_folder}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 extract_smb_attachments.py <pcap_file>")
        sys.exit(1)
    pcap_file = sys.argv[1]
    main(pcap_file)
