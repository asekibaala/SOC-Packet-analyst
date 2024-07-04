import os
import json
import sys
from scapy.all import *
from impacket.smb3 import SMB2Packet, SMB2_FLAGS_REPLY, SMB2_WRITE, SMB2_READ
from impacket.smb import SMB

def parse_pcap(file_path):
    packets = rdpcap(file_path)
    smb2_packets = []

    for packet in packets:
        if packet.haslayer(TCP):
            data = bytes(packet[TCP].payload)
            if data[:4] == b'\xfeSMB':
                smb2_packets.append(packet)

    return smb2_packets

def extract_smb_data(smb2_packets):
    extracted_files = []
    metadata = []

    for packet in smb2_packets:
        data = bytes(packet[TCP].payload)
        smb2_packet = SMB2Packet(data)

        if smb2_packet['Flags'] & SMB2_FLAGS_REPLY:
            continue

        command = smb2_packet['Command']
        if command == SMB2_WRITE:
            file_name = "unknown_write.bin"
            file_size = len(smb2_packet['Data'])
            src_ip = packet[IP].src
            src_port = packet[TCP].sport
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport

            file_info = {
                "file_name": file_name,
                "file_size": file_size,
                "source_ip_address": src_ip,
                "source_port_number": src_port,
                "destination_ip_address": dst_ip,
                "destination_port_number": dst_port
            }
            metadata.append(file_info)

            with open(os.path.join("extracted_files", file_name), "wb") as f:
                f.write(smb2_packet['Data'])
                extracted_files.append(file_name)

        elif command == SMB2_READ:
            file_name = "unknown_read.bin"
            file_size = len(smb2_packet['Data'])
            src_ip = packet[IP].src
            src_port = packet[TCP].sport
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport

            file_info = {
                "file_name": file_name,
                "file_size": file_size,
                "source_ip_address": src_ip,
                "source_port_number": src_port,
                "destination_ip_address": dst_ip,
                "destination_port_number": dst_port
            }
            metadata.append(file_info)

            with open(os.path.join("extracted_files", file_name), "wb") as f:
                f.write(smb2_packet['Data'])
                extracted_files.append(file_name)

    return extracted_files, metadata

def save_metadata(metadata):
    with open("metadata.json", "w") as f:
        json.dump(metadata, f, indent=4)

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 script.py <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    if not os.path.exists("extracted_files"):
        os.makedirs("extracted_files")

    smb2_packets = parse_pcap(pcap_file)
    extracted_files, metadata = extract_smb_data(smb2_packets)
    save_metadata(metadata)

    print(f"Extracted files: {extracted_files}")
    print("Metadata saved to metadata.json")

if __name__ == "__main__":
    main()
