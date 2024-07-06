import json
import sys
from scapy.all import rdpcap

def packet_to_dict(packet):
    packet_dict = {}
    packet_str = packet.show(dump=True)
    lines = packet_str.split('\n')
    current_layer = None
    sub_layer = None
    for line in lines:
        if line.startswith('###[ '):
            current_layer = line[5:-2].strip()
            packet_dict[current_layer] = {}
            sub_layer = None
        elif line.startswith(' | ###[ '):
            sub_layer = line[9:-2].strip()
            if sub_layer not in packet_dict[current_layer]:
                packet_dict[current_layer][sub_layer] = {}
        elif '=' in line:
            key, val = line.split('=', 1)
            key = key.strip()
            val = val.strip()
            if sub_layer:
                packet_dict[current_layer][sub_layer][key] = val
            else:
                packet_dict[current_layer][key] = val
        elif line.startswith(' |'):
            key_val = line.strip().split(' ', 1)
            if len(key_val) == 2:
                key, val = key_val
                key = key.strip()
                val = val.strip()
                if sub_layer:
                    packet_dict[current_layer][sub_layer][key] = val
                else:
                    packet_dict[current_layer][key] = val
    return packet_dict

def main(pcap_file):
    packets = rdpcap(pcap_file)
    packets_info = [packet_to_dict(packet) for packet in packets]

    output_metadata_file = "pcap_data.json"
    with open(output_metadata_file, 'w') as f:
        json.dump(packets_info, f, indent=4)

    print(f"PCAP data has been saved to {output_metadata_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 read_pcap_to_json.py <pcap_file>")
        sys.exit(1)
    pcap_file = sys.argv[1]
    main(pcap_file)
