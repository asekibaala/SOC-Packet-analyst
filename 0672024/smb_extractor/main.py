import sys
from pcap_to_json import convert_pcap_to_json
from extract_attachments import extract_attachments

# Main function to coordinate the conversion and extraction processes
def main(pcap_file):
    json_file = "pcap_data.json"
    output_dir = "outputs"
    metadata_file = "metadata.json"

    convert_pcap_to_json(pcap_file, json_file)  # Convert the pcap file to JSON
    extract_attachments(json_file, output_dir, metadata_file)  # Extract attachments and metadata

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 main.py <pcap_file>")
        sys.exit(1)
    pcap_file = sys.argv[1]
    main(pcap_file)
