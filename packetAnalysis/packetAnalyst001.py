import os
import json
import sys
from scapy.all import *
from impacket.smb3structs import *
from impacket.smb import SMB
from impacket.smbconnection import SMBConnection

def parse_pcap(file_path):
    packets = rdpcap(file_path)
    smb_packets = []

    for packet in packets:
        if SMB in packet:
            smb_packets.append(packet)
    
    return smb_packets

def extract_smb_data(smb_packets):
    extracted_files = []
    metadata = []

    for packet in smb_packets:
        smb_layer = packet[SMB]
        
        if smb_layer.command == SMB.SMB_COM_WRITE:
            file_name = smb_layer.Path
            file_size = len(smb_layer.Data)
            src_ip = packet[IP].src
            src_port = packet[IP].sport
            dst_ip = packet[IP].dst
            dst_port = packet[IP].dport

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
                f.write(smb_layer.Data)
                extracted_files.append(file_name)
        
        elif smb_layer.command == SMB.SMB_COM_READ:
            file_name = smb_layer.Path
            file_size = len(smb_layer.Data)
            src_ip = packet[IP].src
            src_port = packet[IP].sport
            dst_ip = packet[IP].dst
            dst_port = packet[IP].dport

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
                f.write(smb_layer.Data)
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

    smb_packets = parse_pcap(pcap_file)
    extracted_files, metadata = extract_smb_data(smb_packets)
    save_metadata(metadata)

    print(f"Extracted files: {extracted_files}")
    print("Metadata saved to metadata.json")

if __name__ == "__main__":
    main()
