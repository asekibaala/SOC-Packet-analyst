import re

def clean_and_decode_buffer(buffer_str):
    # Remove the outer list and tuple representation
    buffer_str = re.sub(r"\[?\('Output',\s*\"", "", buffer_str)
    buffer_str = re.sub(r"'\)\]?", "", buffer_str)
    
    # Decode the escaped characters
    decoded_bytes = bytes(buffer_str, "utf-8").decode("unicode_escape").encode("latin1")

    return decoded_bytes

def main():
    buffer_str = r"'h-j\\\\\\\\x9e\\\\u058b\\\\\\\\xcf\\\\x01/\\\\\\\\xb5\\\\\\\\x82\\\\\\\\x89\\\\u05cb\\\\\\\\xcf\\\\x01/\\\\\\\\xb5\\\\\\\\x82\\\\\\\\x89\\\\u05cb\\\\\\\\xcf\\\\x01/\\\\\\\\xb5\\\\\\\\x82\\\\\\\\x89\\\\u05cb\\\\\\\\xcf\\\\x01\\\\x10\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x01\\\\x00\\\\x00\\\\x00\\\\x00\\\\x01\\\\x00\\\\x006\\\\\\\\xea\\\\x00\\\\x00\\\\x00\\\\x00\\\\t\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\\\\\x80\\\\x00\\\\x10\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00<\\\\x00\\\\x00\\\\x00\\\\\\\\\\\\x00W\\\\x00i\\\\x00n\\\\x00d\\\\x00o\\\\x00w\\\\x00s\\\\x00\\\\\\\\\\\\x00S\\\\x00Y\\\\x00S\\\\x00V\\\\x00O\\\\x00L\\\\x00\\\\\\\\\\\\x00d\\\\x00o\\\\x00m\\\\x00a\\\\x00i\\\\x00n\\\\x00\\\\\\\\\\\\x00s\\\\x00c\\\\x00r\\\\x00i\\\\x00p\\\\x00t\\\\x00s'"

    decoded_data = clean_and_decode_buffer(buffer_str)
    print("Decoded Data:")
    print(decoded_data)

if __name__ == "__main__":
    main()
