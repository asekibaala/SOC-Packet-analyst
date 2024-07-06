import json
import sys
from scapy.all import rdpcap

def packet_to_dict(packet):
    """Convert a scapy packet to a dictionary."""
    pkt_dict = {
        "timestamp": str(packet.time),  # Convert timestamp to string
        "layers": []
    }

    for layer in packet.layers():
        layer_name = layer.__name__
        layer_dict = {"type": layer_name, "fields": {}}
        for field in layer.fields_desc:
            field_name = field.name
            field_value = getattr(layer, field_name, None)
            if field_value is not None:
                layer_dict["fields"][field_name] = str(field_value)
        pkt_dict["layers"].append(layer_dict)

    return pkt_dict

def extract_frame1(pcap_file):
    packets = rdpcap(pcap_file)
    if len(packets) == 0:
        print("No packets found in the pcap file.")
        return

    frame1 = packets[0]
    frame1_dict = packet_to_dict(frame1)

    output_file = "frame1_info.json"
    with open(output_file, 'w') as f:
        json.dump(frame1_dict, f, indent=4)

    print(f"Frame 1 information has been saved to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 extract_frame1.py <pcap_file>")
        sys.exit(1)
    input_file = sys.argv[1]
    extract_frame1(input_file)
