import json
import sys
import struct
from scapy.all import rdpcap, TCP, Raw

def extract_smb2_info(packet):
    """Extract SMB2 information from a packet."""
    smb2_info = {}
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load
        if len(payload) >= 4:
            protocol_id = struct.unpack(">I", payload[:4])[0]
            if protocol_id == 0xfe534d42:  # Check if the protocol identifier matches SMB2
                smb2_info = {
                    "SMB_Protocol": "SMB2",
                    "data": payload.hex()
                }
    return smb2_info

def extract_frame1_smb2(pcap_file):
    packets = rdpcap(pcap_file)
    if len(packets) == 0:
        print("No packets found in the pcap file.")
        return

    frame1 = packets[0]
    smb2_info = extract_smb2_info(frame1)
    
    if not smb2_info:
        print("Frame 1 does not contain SMB2 information.")
        return

    output_file = "frame1_smb2_info.json"
    with open(output_file, 'w') as f:
        json.dump(smb2_info, f, indent=4)

    print(f"Frame 1 SMB2 information has been saved to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 extract_smb2_info_by_protocol.py <pcap_file>")
        sys.exit(1)
    input_file = sys.argv[1]
    extract_frame1_smb2(input_file)
