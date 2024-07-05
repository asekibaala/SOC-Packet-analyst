import os
import json
import sys
from scapy.all import rdpcap, TCP, IP

# Define constants for SMB2
SMB2_SIGNATURE = b'\xfeSMB'
SMB2_WRITE_REQUEST = 0x0009
SMB2_READ_RESPONSE = 0x0004

def parse_pcap(file_path):
    packets = rdpcap(file_path)
    smb2_packets = []

    for packet in packets:
        if packet.haslayer(TCP):
            data = bytes(packet[TCP].payload)
            if data[:4] == SMB2_SIGNATURE:
                smb2_packets.append(packet)

    print(f"Identified {len(smb2_packets)} SMB2 packets")
    return smb2_packets

def extract_smb_data(smb2_packets):
    extracted_files = []
    metadata = []

    for packet in smb2_packets:
        data = bytes(packet[TCP].payload)
        command = int.from_bytes(data[12:14], byteorder='little')

        if command == SMB2_WRITE_REQUEST:
            success = process_smb2_write_request(packet, data, extracted_files, metadata)
            if success:
                print(f"Processed SMB2 Write Request: {success}")
        
        elif command == SMB2_READ_RESPONSE:
            success = process_smb2_read_response(packet, data, extracted_files, metadata)
            if success:
                print(f"Processed SMB2 Read Response: {success}")
    
    return extracted_files, metadata

def process_smb2_write_request(packet, data, extracted_files, metadata):
    file_name = f"write_{len(extracted_files)}.bin"
    src_ip = packet[IP].src
    src_port = packet[TCP].sport
    dst_ip = packet[IP].dst
    dst_port = packet[TCP].dport
    
    # Extract the write data from the packet
    write_data_offset = int.from_bytes(data[56:60], byteorder='little') + 64  # Adjusted based on SMB2 header size
    write_data_length = int.from_bytes(data[60:64], byteorder='little')
    write_data = data[write_data_offset:write_data_offset + write_data_length]

    if write_data:
        file_info = {
            "file_name": file_name,
            "file_size": len(write_data),
            "source_ip_address": src_ip,
            "source_port_number": src_port,
            "destination_ip_address": dst_ip,
            "destination_port_number": dst_port
        }
        metadata.append(file_info)

        with open(os.path.join("extracted_files", file_name), "wb") as f:
            f.write(write_data)
            extracted_files.append(file_name)
        return True
    return False

def process_smb2_read_response(packet, data, extracted_files, metadata):
    file_name = f"read_{len(extracted_files)}.bin"
    src_ip = packet[IP].src
    src_port = packet[TCP].sport
    dst_ip = packet[IP].dst
    dst_port = packet[TCP].dport
    
    # Extract the read data from the packet
    read_data_offset = int.from_bytes(data[56:60], byteorder='little') + 64  # Adjusted based on SMB2 header size
    read_data_length = int.from_bytes(data[60:64], byteorder='little')
    read_data = data[read_data_offset:read_data_offset + read_data_length]

    if read_data:
        file_info = {
            "file_name": file_name,
            "file_size": len(read_data),
            "source_ip_address": src_ip,
            "source_port_number": src_port,
            "destination_ip_address": dst_ip,
            "destination_port_number": dst_port
        }
        metadata.append(file_info)

        with open(os.path.join("extracted_files", file_name), "wb") as f:
            f.write(read_data)
            extracted_files.append(file_name)
        return True
    return False

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
