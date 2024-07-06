import os
import json
import base64
import sys
from datetime import datetime
from scapy.all import rdpcap

def packet_to_dict(packet):
    packet_dict = {}
    packet_str = packet.show(dump=True)
    lines = packet_str.split('\n')
    for line in lines:
        if line.startswith('###[ '):
            layer_name = line[5:-2].strip()
            packet_dict[layer_name] = {}
        elif '=' in line:
            key, val = line.split('=', 1)
            key = key.strip()
            val = val.strip()
            packet_dict[layer_name][key] = val
    return packet_dict

def convert_pcap_to_json(pcap_file, json_file):
    packets = rdpcap(pcap_file)
    packets_info = [packet_to_dict(packet) for packet in packets]

    with open(json_file, 'w') as f:
        json.dump(packets_info, f, indent=4)

    print(f"PCAP data has been saved to {json_file}")

def is_base64(s):
    try:
        if isinstance(s, str):
            s_bytes = s.encode('ascii')
        elif isinstance(s, bytes):
            s_bytes = s
        else:
            raise ValueError("Input must be a string or bytes")
        return base64.b64encode(base64.b64decode(s_bytes)) == s_bytes
    except Exception:
        return False

def extract_timestamp_from_options(options):
    try:
        for opt in eval(options):
            if opt[0] == 'Timestamp':
                ts_val = opt[1][0]
                return datetime.fromtimestamp(ts_val).strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        print(f"Failed to extract timestamp from options: {e}")
    return "N/A"

def extract_attachments(json_file, output_dir, metadata_file):
    with open(json_file, 'r') as f:
        pcap_data = json.load(f)

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    metadata = []

    for packet in pcap_data:
        smb2_header = packet.get("SMB2 Header ]##")
        if smb2_header and smb2_header.get("Command") in ["SMB2_WRITE", "SMB2_READ"]:
            file_name = f"attachment_{smb2_header['MID']}_{smb2_header['Command']}.bin"
            file_size = 0

            if smb2_header["Command"] == "SMB2_WRITE":
                smb2_write = packet.get("SMB2 WRITE Request ]##")
                if smb2_write:
                    buffer_data = smb2_write.get("Buffer")
                    if buffer_data:
                        try:
                            if is_base64(buffer_data):
                                attachment_data = base64.b64decode(buffer_data)
                            else:
                                attachment_data = buffer_data.encode('utf-8')
                            file_size = len(attachment_data)
                            file_path = os.path.join(output_dir, file_name)
                            with open(file_path, 'wb') as attachment_file:
                                attachment_file.write(attachment_data)
                        except Exception as e:
                            print(f"Failed to decode/write attachment: {e}")

            if smb2_header["Command"] == "SMB2_READ":
                smb2_read = packet.get("SMB2 READ Response ]##")
                if smb2_read:
                    buffer_data = smb2_read.get("Buffer")
                    if buffer_data:
                        try:
                            if is_base64(buffer_data):
                                attachment_data = base64.b64decode(buffer_data)
                            else:
                                attachment_data = buffer_data.encode('utf-8')
                            file_size = len(attachment_data)
                            file_path = os.path.join(output_dir, file_name)
                            with open(file_path, 'wb') as attachment_file:
                                attachment_file.write(attachment_data)
                        except Exception as e:
                            print(f"Failed to decode/write attachment: {e}")

            timestamp = extract_timestamp_from_options(packet.get("TCP ]##", {}).get("options", "[]"))

            metadata.append({
                "file_name": file_name,
                "file_size": file_size,
                "source_ip": packet.get("IP ]##", {}).get("src"),
                "source_port": packet.get("TCP ]##", {}).get("sport"),
                "destination_ip": packet.get("IP ]##", {}).get("dst"),
                "destination_port": packet.get("TCP ]##", {}).get("dport"),
                "timestamp": timestamp
            })

    with open(metadata_file, 'w') as metadata_f:
        json.dump(metadata, metadata_f, indent=4)
    print(f"Metadata has been saved to {metadata_file}")

def main(pcap_file):
    json_file = "pcap_data.json"
    output_dir = "outputs"
    metadata_file = "metadata.json"

    convert_pcap_to_json(pcap_file, json_file)
    extract_attachments(json_file, output_dir, metadata_file)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 main.py <pcap_file>")
        sys.exit(1)
    pcap_file = sys.argv[1]
    main(pcap_file)
