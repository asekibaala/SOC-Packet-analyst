from scapy.all import rdpcap, Raw

# Load the pcap file
pcap_file = "smb.pcap"  # Change this to your actual file path
packets = rdpcap(pcap_file)

# Count total number of packets
total_packets = len(packets)
print(f"Total packets: {total_packets}")

# Filter for packets that start with SMB2 header (0xFE 'S' 'M' 'B')
smb2_packets = [pkt for pkt in packets if pkt.haslayer(Raw) and pkt[Raw].load.startswith(b'\xfeSMB')]

# Count total number of SMB2 packets
total_smb2_packets = len(smb2_packets)
print(f"Total SMB2 packets: {total_smb2_packets}")

# Print first few SMB2 packets for inspection
for i, pkt in enumerate(smb2_packets[:5]):
    print(f"SMB2 Packet {i + 1}: {pkt[Raw].load[:100].hex()}")
