import json
from scapy.all import *
from scapy.layers.smb import *

def extract_smbv2_data(pcap_file):
    packets = rdpcap(pcap_file)
    metadata = []
    for packet in packets:
        if packet.haslayer(SMB2):
            smb = packet[SMB2]
            if smb.Command == 9:  # Write Request
                filename = smb.FileName
                filesize = smb.EndofFile
                src_ip = packet[IP].src
                src_port = packet[TCP].sport
                dst_ip = packet[IP].dst
                dst_port = packet[TCP].dport
                metadata.append({
                    'filename': filename,
                    'filesize': filesize,
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                })
                with open(f'extracted_files/{filename}', 'wb') as f:
                    f.write(smb.Data)
    with open('metadata.json', 'w') as f:
        json.dump(metadata, f)

if __name__ == "__main__":
    import sys
    extract_smbv2_data(sys.argv[1])