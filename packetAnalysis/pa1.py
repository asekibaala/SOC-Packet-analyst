from scapy.all import *

def parse_pcap(pcap_file):
    smb_packets = []
    try:
        packets = rdpcap(pcap_file)
        for packet in packets:
            if SMB2Packet in packet:
                smb_packets.append(packet)
    except Exception as e:
        print(f"Error reading pcap file: {e}")
    
    return smb_packets

# Example usage
if __name__ == "__main__":
    pcap_file = "smb.pcap"
    smb_packets = parse_pcap(pcap_file)
    print(f"Found {len(smb_packets)} SMBv2 packets.")
