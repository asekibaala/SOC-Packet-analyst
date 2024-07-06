import os
import json
import base64
from datetime import datetime

def is_base64(s):
    try:
        if isinstance(s, str):
            s_bytes = s.encode('ascii')
        elif isinstance(s, bytes):
            s_bytes = s
        else:
            raise ValueError("Input must be a string or bytes")
        return base64.b64encode(base64.b64decode(s_bytes)) == s_bytes
    except Exception:
        return False

def extract_attachments(json_file, output_dir, metadata_file):
    with open(json_file, 'r') as f:
        pcap_data = json.load(f)

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    metadata = []

    for packet in pcap_data:
        smb2_header = packet.get("SMB2 Header ]##")
        if smb2_header and smb2_header.get("Command") in ["SMB2_WRITE", "SMB2_READ"]:
            file_name = f"attachment_{smb2_header['MID']}_{smb2_header['Command']}.bin"
            file_size = 0

            if smb2_header["Command"] == "SMB2_WRITE":
                smb2_write = packet.get("SMB2 WRITE Request ]##")
                if smb2_write:
                    buffer_data = smb2_write.get("Buffer")
                    if buffer_data:
                        try:
                            if is_base64(buffer_data):
                                attachment_data = base64.b64decode(buffer_data)
                            else:
                                attachment_data = buffer_data.encode('utf-8')
                            file_size = len(attachment_data)
                            file_path = os.path.join(output_dir, file_name)
                            with open(file_path, 'wb') as attachment_file:
                                attachment_file.write(attachment_data)
                        except Exception as e:
                            print(f"Failed to decode/write attachment: {e}")

            if smb2_header["Command"] == "SMB2_READ":
                smb2_read = packet.get("SMB2 READ Response ]##")
                if smb2_read:
                    buffer_data = smb2_read.get("Buffer")
                    if buffer_data:
                        try:
                            if is_base64(buffer_data):
                                attachment_data = base64.b64decode(buffer_data)
                            else:
                                attachment_data = buffer_data.encode('utf-8')
                            file_size = len(attachment_data)
                            file_path = os.path.join(output_dir, file_name)
                            with open(file_path, 'wb') as attachment_file:
                                attachment_file.write(attachment_data)
                        except Exception as e:
                            print(f"Failed to decode/write attachment: {e}")

            timestamp = packet.get("timestamp")
            if timestamp:
                try:
                    timestamp = datetime.fromtimestamp(float(timestamp)).strftime('%Y-%m-%d %H:%M:%S')
                except Exception as e:
                    print(f"Failed to convert timestamp: {e}")
                    timestamp = "N/A"

            metadata.append({
                "file_name": file_name,
                "file_size": file_size,
                "source_ip": packet.get("IP ]##", {}).get("src"),
                "source_port": packet.get("TCP ]##", {}).get("sport"),
                "destination_ip": packet.get("IP ]##", {}).get("dst"),
                "destination_port": packet.get("TCP ]##", {}).get("dport"),
                "timestamp": timestamp
            })

    with open(metadata_file, 'w') as metadata_f:
        json.dump(metadata, metadata_f, indent=4)
    print(f"Metadata has been saved to {metadata_file}")

if __name__ == "__main__":
    json_file = "pcap_data.json"
    output_dir = "outputs"
    metadata_file = "metadata.json"
    extract_attachments(json_file, output_dir, metadata_file)
