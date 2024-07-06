import json
from scapy.all import rdpcap

# Function to convert a packet to a dictionary
def packet_to_dict(packet):
    packet_dict = {}
    packet_str = packet.show(dump=True)  # Get the packet details as a string
    lines = packet_str.split('\n')  # Split the string into lines
    for line in lines:
        if line.startswith('###[ '):
            layer_name = line[5:-2].strip()  # Extract the layer name
            packet_dict[layer_name] = {}  # Initialize a dictionary for the layer
        elif '=' in line:
            key, val = line.split('=', 1)  # Split the line into key and value
            key = key.strip()
            val = val.strip()
            packet_dict[layer_name][key] = val  # Add the key-value pair to the layer dictionary
    return packet_dict

# Function to convert a pcap file to a JSON file
def convert_pcap_to_json(pcap_file, json_file):
    packets = rdpcap(pcap_file)  # Read the pcap file
    packets_info = [packet_to_dict(packet) for packet in packets]  # Convert each packet to a dictionary

    with open(json_file, 'w') as f:
        json.dump(packets_info, f, indent=4)  # Save the packet information to a JSON file

    print(f"PCAP data has been saved to {json_file}")
