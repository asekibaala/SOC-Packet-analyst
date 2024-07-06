import os
import json
import sys
from scapy.all import rdpcap, TCP, Raw, IP

# Create a folder to store the extracted metadata
folder_name = 'extracted_files'
if not os.path.exists(folder_name):
    os.mkdir(folder_name)

def extract_filenames(packet):
    """Extract filenames from a packet."""
    filenames = []
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        # Look for common file name patterns
        if b'.' in payload:
            parts = payload.split(b'.')
            for i in range(len(parts) - 1):
                try:
                    name_part = parts[i].split()[-1]
                    ext_part = parts[i + 1].split()[0]
                    filename = name_part + b'.' + ext_part
                    if len(filename) < 255 and all(chr(c).isalnum() or chr(c) in '._-' for c in filename):
                        filenames.append(filename.decode('utf-8', errors='ignore'))
                except IndexError:
                    continue
    return filenames

class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.decode('utf-8', errors='ignore')
        if isinstance(obj, float):
            return str(obj)
        if isinstance(obj, int):
            return str(obj)
        if hasattr(obj, 'isoformat'):
            return obj.isoformat()
        if type(obj).__name__ == 'EDecimal':
            return str(obj)
        return super().default(obj)

def convert_to_serializable(packet):
    """Convert packet metadata to a serializable dictionary."""
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        return {
            "src_ip": repr(ip_layer.src),
            "src_port": tcp_layer.sport,
            "dst_ip": repr(ip_layer.dst),
            "dst_port": tcp_layer.dport,
            "timestamp": packet.time
        }
    return {}

def main(pcap_file):
    scapy_cap = rdpcap(pcap_file)
    filenames_info = []

    for packet in scapy_cap:
        if packet.haslayer(IP) and packet.haslayer(TCP):
            filenames = extract_filenames(packet)
            if filenames:
                metadata = convert_to_serializable(packet)
                for filename in filenames:
                    file_metadata = {
                        "file_name": filename,
                    }
                    file_metadata.update(metadata)
                    filenames_info.append(file_metadata)

    output_metadata_file = os.path.join(folder_name, "filenames_metadata.json")
    with open(output_metadata_file, 'w') as f:
        json.dump(filenames_info, f, indent=4, cls=CustomJSONEncoder)
    print(f"Filename information has been saved to {output_metadata_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 extract_filenames.py <pcap_file>")
        sys.exit(1)
    pcap_file = sys.argv[1]
    main(pcap_file)
