from scapy.all import Ether, IP, TCP, wrpcap, Raw

def generate_pcap(filename):
    packets = []

    # Create a sample packet with SMB2 Write Request
    smb2_write_request = b'\xfeSMB' + b'\x00' * 60 + b'\x09' + b'\x00' * 3 + b'\x00' * 48 + b'write_request_data'
    ether = Ether()
    ip = IP(src="192.168.1.1", dst="192.168.1.2")
    tcp = TCP(sport=445, dport=12345)
    raw = Raw(load=smb2_write_request)
    packet = ether / ip / tcp / raw
    packets.append(packet)

    # Create a sample packet with SMB2 Write Response
    smb2_write_response = b'\xfeSMB' + b'\x00' * 60 + b'\x10' + b'\x00' * 3 + b'\x00' * 48 + b'write_response_data'
    ether = Ether()
    ip = IP(src="192.168.1.2", dst="192.168.1.1")
    tcp = TCP(sport=12345, dport=445)
    raw = Raw(load=smb2_write_response)
    packet = ether / ip / tcp / raw
    packets.append(packet)

    # Create a sample packet with SMB2 Read Request
    smb2_read_request = b'\xfeSMB' + b'\x00' * 60 + b'\x08' + b'\x00' * 3 + b'\x00' * 48 + b'read_request_data'
    ether = Ether()
    ip = IP(src="192.168.1.1", dst="192.168.1.2")
    tcp = TCP(sport=445, dport=12345)
    raw = Raw(load=smb2_read_request)
    packet = ether / ip / tcp / raw
    packets.append(packet)

    # Create a sample packet with SMB2 Read Response
    smb2_read_response = b'\xfeSMB' + b'\x00' * 60 + b'\x11' + b'\x00' * 3 + b'\x00' * 48 + b'read_response_data'
    ether = Ether()
    ip = IP(src="192.168.1.2", dst="192.168.1.1")
    tcp = TCP(sport=12345, dport=445)
    raw = Raw(load=smb2_read_response)
    packet = ether / ip / tcp / raw
    packets.append(packet)

    # Write the packets to a pcap file
    wrpcap(filename, packets)
    print(f"Generated pcap file: {filename}")

if __name__ == "__main__":
    generate_pcap("sample_smb.pcap")
