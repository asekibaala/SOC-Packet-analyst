import dpkt
import socket
import json
import os

# Define constants for SMB2
SMB2_HEADER_SIZE = 64
SMB2_SIGNATURE = b'\xfeSMB'

# Function to parse the SMB2 packet
def parse_smb2_packet(data):
    # Check SMB2 signature
    if len(data) < SMB2_HEADER_SIZE or data[:4] != SMB2_SIGNATURE:
        return None

    # Extract SMB2 header fields
    flags = data[12]
    command = int.from_bytes(data[16:18], byteorder='little')
    message_id = int.from_bytes(data[28:36], byteorder='little')
    
    return {
        'flags': flags,
        'command': command,
        'message_id': message_id,
        'data': data[SMB2_HEADER_SIZE:]
    }

# Function to extract and print debug information from SMB2 packets
def extract_smb2_data(pcap_file):
    extracted_files = []
    metadata = []

    # Check if the pcap file exists
    if not os.path.isfile(pcap_file):
        print(f"File not found: {pcap_file}")
        return extracted_files, metadata

    # Open the pcap file
    try:
        with open(pcap_file, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)

            for timestamp, buf in pcap:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                if not isinstance(ip.data, dpkt.tcp.TCP):
                    continue
                tcp = ip.data

                # Check for SMB2 packets
                if tcp.dport == 445 or tcp.sport == 445:
                    data = tcp.data
                    smb2_packet = parse_smb2_packet(data)
                    if smb2_packet:
                        # Extract relevant fields and print debug information
                        flags = smb2_packet['flags']
                        command = smb2_packet['command']
                        message_id = smb2_packet['message_id']
                        payload_data = smb2_packet['data']

                        print(f'Flags: {flags}, Command: {command}, Message ID: {message_id}')
                        print(f'Payload data: {payload_data[:20]}...')

                        # Handle specific SMB2 commands
                        if command == 0x05:  # Create Response
                            print('Create Response detected.')
                            # Parse specific fields for Create Response if needed

                        elif command == 0x0E:  # Find Response
                            print('Find Response detected.')
                            # Parse specific fields for Find Response if needed

                        elif command == 0x06:  # Close Response
                            print('Close Response detected.')
                            # Parse specific fields for Close Response if needed

                        metadata.append({
                            'flags': flags,
                            'command': command,
                            'message_id': message_id,
                            'source_ip': socket.inet_ntoa(ip.src),
                            'source_port': tcp.sport,
                            'destination_ip': socket.inet_ntoa(ip.dst),
                            'destination_port': tcp.dport,
                            'timestamp': timestamp,
                        })

    except FileNotFoundError:
        print(f"File not found: {pcap_file}")
    except Exception as e:
        print(f"An error occurred: {e}")

    return extracted_files, metadata

# Run the function and save metadata to JSON
pcap_file_path = 'smb.pcap'  # Update this path to the correct location of your pcap file
extracted_files, metadata = extract_smb2_data(pcap_file_path)
print(f'Extracted files: {extracted_files}')
print(f'Metadata: {metadata}')

with open('metadata.json', 'w') as f:
    json.dump(metadata, f, indent=4)
print('Metadata saved to metadata.json')
