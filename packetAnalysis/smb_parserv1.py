import json
import os
import sys
from scapy.all import rdpcap, TCP, Raw
from scapy.layers.inet import IP

def read_pcap(file_path):
    packets = rdpcap(file_path)
    smb_packets = []
    for packet in packets:
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            payload = packet[Raw].load
            if payload.startswith(b"\xfeSMB"):  # SMB2 packets start with 0xFE 'S' 'M' 'B'
                smb_packets.append(packet)
    return smb_packets

def parse_smb2_write_request(payload):
    if len(payload) < 113:  # Ensure the packet is at least as large as the SMB2 header + minimum write request size
        return None
    structure_size = int.from_bytes(payload[64:66], byteorder='little')
    if structure_size != 49:
        return None

    data_offset = int.from_bytes(payload[66:68], byteorder='little')
    data_length = int.from_bytes(payload[68:72], byteorder='little')
    offset = int.from_bytes(payload[72:80], byteorder='little')
    file_id = payload[80:96]
    channel = int.from_bytes(payload[96:100], byteorder='little')
    remaining_bytes = int.from_bytes(payload[100:104], byteorder='little')
    write_channel_info_offset = int.from_bytes(payload[104:106], byteorder='little')
    write_channel_info_length = int.from_bytes(payload[106:108], byteorder='little')
    flags = int.from_bytes(payload[108:112], byteorder='little')
    buffer_data = payload[data_offset:data_offset + data_length]

    return {
        "structure_size": structure_size,
        "data_offset": data_offset,
        "data_length": data_length,
        "offset": offset,
        "file_id": file_id,
        "channel": channel,
        "remaining_bytes": remaining_bytes,
        "write_channel_info_offset": write_channel_info_offset,
        "write_channel_info_length": write_channel_info_length,
        "flags": flags,
        "buffer_data": buffer_data
    }

def parse_smb2_write_response(payload):
    if len(payload) < 81:  # Ensure the packet is at least as large as the SMB2 header + minimum write response size
        return None
    structure_size = int.from_bytes(payload[64:66], byteorder='little')
    if structure_size != 17:
        return None

    reserved = int.from_bytes(payload[66:68], byteorder='little')
    count = int.from_bytes(payload[68:72], byteorder='little')
    remaining = int.from_bytes(payload[72:76], byteorder='little')
    write_channel_info_offset = int.from_bytes(payload[76:78], byteorder='little')
    write_channel_info_length = int.from_bytes(payload[78:80], byteorder='little')

    return {
        "structure_size": structure_size,
        "reserved": reserved,
        "count": count,
        "remaining": remaining,
        "write_channel_info_offset": write_channel_info_offset,
        "write_channel_info_length": write_channel_info_length
    }

def extract_smb_data(smb_packets):
    smb_data = []
    for packet in smb_packets:
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        raw_data = packet[Raw].load

        smb_header = raw_data[:64]
        smb_command = smb_header[12:14]

        if smb_command == b"\x09\x00":  # SMB2 Write Request
            smb_write_request = parse_smb2_write_request(raw_data)
            if smb_write_request:
                metadata = {
                    "src_ip": ip_layer.src,
                    "src_port": tcp_layer.sport,
                    "dst_ip": ip_layer.dst,
                    "dst_port": tcp_layer.dport,
                    "timestamp": packet.time,
                }
                smb_data.append((smb_write_request["buffer_data"], metadata))

        elif smb_command == b"\x0A\x00":  # SMB2 Write Response
            smb_write_response = parse_smb2_write_response(raw_data)
            if smb_write_response:
                metadata = {
                    "src_ip": ip_layer.src,
                    "src_port": tcp_layer.sport,
                    "dst_ip": ip_layer.dst,
                    "dst_port": tcp_layer.dport,
                    "timestamp": packet.time,
                }
                smb_data.append((smb_write_response, metadata))
    
    return smb_data

def reconstruct_files(smb_data):
    files = {}
    for data, metadata in smb_data:
        filename = "extracted_file.txt"
        
        if filename not in files:
            files[filename] = {"data": b"", "metadata": []}
        if isinstance(data, dict) and "buffer_data" in data:
            files[filename]["data"] += data["buffer_data"]
        else:
            files[filename]["data"] += data
        
        files[filename]["metadata"].append(metadata)

    return files

def save_files(files, output_folder):
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    metadata_list = []
    for filename, file_info in files.items():
        file_path = os.path.join(output_folder, filename)
        with open(file_path, "wb") as f:
            f.write(file_info["data"])
        
        file_metadata = {
            "file_name": filename,
            "file_size": len(file_info["data"]),
            "metadata": file_info["metadata"]
        }
        metadata_list.append(file_metadata)
    
    with open(os.path.join(output_folder, "metadata.json"), "w") as f:
        json.dump(metadata_list, f, indent=4)

def main(input_file):
    smb_packets = read_pcap(input_file)
    print(f"Total SMBv2 packets found: {len(smb_packets)}")
    smb_data = extract_smb_data(smb_packets)
    if smb_data:
        files = reconstruct_files(smb_data)
        save_files(files, "output")
    else:
        print("No SMBv2 write requests or responses found.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 smb_parser.py <pcap_file>")
        sys.exit(1)
    input_file = sys.argv[1]
    main(input_file)
