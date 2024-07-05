import json
import sys
from scapy.all import rdpcap, Ether, IP, TCP, Raw

def convert_to_serializable(value):
    """Convert Scapy values to serializable types."""
    if isinstance(value, (bytes, bytearray)):
        return value.hex()
    elif isinstance(value, (list, tuple)):
        return [convert_to_serializable(v) for v in value]
    elif isinstance(value, dict):
        return {k: convert_to_serializable(v) for k, v in value.items()}
    elif hasattr(value, "value"):
        return str(value)  # Convert FlagValue and other Scapy custom types to string
    return value

def extract_tcp_info(packet):
    """Extract TCP information from a packet."""
    tcp_info = {}
    if packet.haslayer(Ether) and packet.haslayer(IP) and packet.haslayer(TCP):
        eth_layer = packet[Ether]
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        tcp_info = {
            "eth_src": eth_layer.src,
            "eth_dst": eth_layer.dst,
            "ip_src": ip_layer.src,
            "ip_dst": ip_layer.dst,
            "ip_version": convert_to_serializable(ip_layer.version),
            "ip_ihl": convert_to_serializable(ip_layer.ihl),
            "ip_tos": convert_to_serializable(ip_layer.tos),
            "ip_len": convert_to_serializable(ip_layer.len),
            "ip_id": convert_to_serializable(ip_layer.id),
            "ip_flags": convert_to_serializable(ip_layer.flags),
            "ip_frag": convert_to_serializable(ip_layer.frag),
            "ip_ttl": convert_to_serializable(ip_layer.ttl),
            "ip_proto": convert_to_serializable(ip_layer.proto),
            "ip_chksum": convert_to_serializable(ip_layer.chksum),
            "tcp_sport": convert_to_serializable(tcp_layer.sport),
            "tcp_dport": convert_to_serializable(tcp_layer.dport),
            "tcp_seq": convert_to_serializable(tcp_layer.seq),
            "tcp_ack": convert_to_serializable(tcp_layer.ack),
            "tcp_dataofs": convert_to_serializable(tcp_layer.dataofs),
            "tcp_reserved": convert_to_serializable(tcp_layer.reserved),
            "tcp_flags": convert_to_serializable(tcp_layer.flags),
            "tcp_window": convert_to_serializable(tcp_layer.window),
            "tcp_chksum": convert_to_serializable(tcp_layer.chksum),
            "tcp_urgptr": convert_to_serializable(tcp_layer.urgptr)
        }
        if packet.haslayer(Raw):
            tcp_info["payload"] = convert_to_serializable(packet[Raw].load)
    return tcp_info

def main(pcap_file):
    scapy_cap = rdpcap(pcap_file)
    tcp_packets_info = []

    for packet in scapy_cap:
        tcp_info = extract_tcp_info(packet)
        if tcp_info:
            tcp_packets_info.append(tcp_info)

    if tcp_packets_info:
        output_file = "tcp_packets_info.json"
        with open(output_file, 'w') as f:
            json.dump(tcp_packets_info, f, indent=4)
        print(f"TCP information has been saved to {output_file}")
    else:
        print("No TCP packets found.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 extract_all_tcp_info.py <pcap_file>")
        sys.exit(1)
    pcap_file = sys.argv[1]
    main(pcap_file)
