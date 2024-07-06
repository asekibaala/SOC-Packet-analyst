import json
import sys
import pyshark

def extract_smb2_create_info(packet):
    smb2_info = {}
    if 'SMB2' in packet:
        smb2_layer = packet['SMB2']
        if smb2_layer.smb2_cmd == '5':  # SMB2 Create Request
            smb2_info = {
                "command": "Create Request",
                "src_ip": packet.ip.src,
                "src_port": packet.tcp.srcport,
                "dst_ip": packet.ip.dst,
                "dst_port": packet.tcp.dstport,
                "timestamp": packet.sniff_time.isoformat(),
                "file_name": smb2_layer.get_field_value('smb2.filename')
            }
    return smb2_info

def main(pcap_file):
    capture = pyshark.FileCapture(pcap_file)
    smb2_info_list = []

    for packet in capture:
        smb2_info = extract_smb2_create_info(packet)
        if smb2_info:
            smb2_info_list.append(smb2_info)

    capture.close()

    output_metadata_file = "smb2_create_requests_metadata.json"
    with open(output_metadata_file, 'w') as f:
        json.dump(smb2_info_list, f, indent=4)
    print(f"SMB2 Create Request information has been saved to {output_metadata_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 detect_smb2_create_requests_pyshark.py <pcap_file>")
        sys.exit(1)
    pcap_file = sys.argv[1]
    main(pcap_file)
