import json
import sys
import os

def extract_smb2_read_info(pcap_data):
    smb2_read_info = []
    extracted_files = {}

    for packet in pcap_data:
        smb2_info = {}
        if "SMB2 Header ]##" in packet:
            smb2_header = packet["SMB2 Header ]##"]
            if "Command" in smb2_header:
                command = smb2_header["Command"]
                if command == "SMB2_READ" and "SMB2 READ Request ]##" in packet:
                    smb2_read_request = packet["SMB2 READ Request ]##"]
                    smb2_info = {
                        "command": "SMB2_READ_REQUEST",
                        "src_ip": packet["IP ]##"]["src"],
                        "dst_ip": packet["IP ]##"]["dst"],
                        "timestamp": packet.get("timestamp", "N/A"),
                        "length": smb2_read_request.get("Length", "N/A"),
                        "offset": smb2_read_request.get("Offset", "N/A"),
                        "persistent": smb2_read_request.get("|  Persistent", "N/A"),
                        "volatile": smb2_read_request.get("|  Volatile", "N/A")
                    }
                    smb2_read_info.append(smb2_info)
                elif command == "SMB2_READ" and "SMB2 READ Response ]##" in packet:
                    smb2_read_response = packet["SMB2 READ Response ]##"]
                    smb2_info = {
                        "command": "SMB2_READ_RESPONSE",
                        "src_ip": packet["IP ]##"]["src"],
                        "dst_ip": packet["IP ]##"]["dst"],
                        "timestamp": packet.get("timestamp", "N/A"),
                        "data_length": smb2_read_response.get("DataLength", "N/A"),
                        "data_offset": smb2_read_response.get("DataOffset", "N/A"),
                    }

                    if "Buffer" in smb2_read_response:
                        data = smb2_read_response["Buffer"]
                        if isinstance(data, str):
                            try:
                                # Decoding the data
                                file_data = bytes(data, 'utf-8')
                                file_name = f"file_{len(extracted_files) + 1}.dat"
                                extracted_files[file_name] = file_data

                                smb2_info["file_name"] = file_name
                                smb2_info["file_size"] = len(file_data)
                            except Exception as e:
                                print(f"Failed to decode data: {e}")
                                smb2_info["file_name"] = "N/A"
                                smb2_info["file_size"] = 0

                    smb2_read_info.append(smb2_info)

    return smb2_read_info, extracted_files

def main(json_file):
    with open(json_file, 'r') as f:
        pcap_data = json.load(f)

    smb2_read_info, extracted_files = extract_smb2_read_info(pcap_data)

    output_metadata_file = "smb2_read_info.json"
    with open(output_metadata_file, 'w') as f:
        json.dump(smb2_read_info, f, indent=4)
    print(f"SMB2 Read Request and Response information has been saved to {output_metadata_file}")

    output_folder = "extracted_files"
    os.makedirs(output_folder, exist_ok=True)
    for file_name, file_data in extracted_files.items():
        file_path = os.path.join(output_folder, file_name)
        with open(file_path, 'wb') as f:
            f.write(file_data)
    print(f"Extracted files have been saved to the '{output_folder}' folder")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 smb2_extract_read.py <json_file>")
        sys.exit(1)
    json_file = sys.argv[1]
    main(json_file)
