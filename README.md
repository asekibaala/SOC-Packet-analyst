# SMBv2 Packet Extractor

## Description

This program reads a PCAP file, extracts SMBv2 packets, and retrieves attachments and metadata from file read and write operations. The extracted files are saved in a folder, and the metadata is saved in a JSON file.

## Prerequisites

- Python 3.x
- Required Python packages:
  - scapy
  - impacket

## Installation

1. Install the required Python packages:
   ```sh
   pip install scapy impacket

### Notes:

1. **Parsing SMB without Wireshark**: The program uses the `scapy` library to parse the PCAP file and identify SMB packets. It then uses the `impacket` library to handle SMB structures.
2. **Handling SMB Read and Write Requests**: The program extracts the SMB write and read requests from the packets and saves the data to files.
3. **Metadata**: The program collects metadata for each file and saves it in a JSON file.

### How to Run

1. Ensure you have the required libraries installed.
2. Save the Python script to a file, e.g., `extract_smb.py`.
3. Create a folder named `extracted_files` in the same directory as the script.
4. Run the script with a PCAP file as an argument:

```sh
python3 extract_smb.py <pcap_file>
