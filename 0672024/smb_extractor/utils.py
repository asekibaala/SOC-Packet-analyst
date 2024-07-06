import base64
from datetime import datetime

# Function to check if a string is base64 encoded
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

# Function to extract a timestamp from TCP options
def extract_timestamp_from_options(options):
    try:
        for opt in eval(options):
            if opt[0] == 'Timestamp':
                ts_val = opt[1][0]
                return datetime.fromtimestamp(ts_val).strftime('%Y-%m-%d %H:%M:%S')  # Convert the timestamp to human-readable format
    except Exception as e:
        print(f"Failed to extract timestamp from options: {e}")
    return "N/A"
