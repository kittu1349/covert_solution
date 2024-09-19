# just run python3 covert_solve.py
from scapy.all import rdpcap, IP

def generate_encoded_ascii_dict(message, max_key=100):
    """
    Generate a dictionary of encoded ASCII values for each key from 0 to max_key.
    
    :param message: The string message to encode
    :param max_key: The maximum key value to use for encoding
    :return: A dictionary where keys are encoded ASCII values and values are the corresponding keys
    """
    encoded_dict = {}
    for key in range(1, max_key + 1):  # Avoid key = 0 to prevent multiplication by zero
        for char in message:
            encoded_ord = ord(char) * key
            encoded_dict[encoded_ord] = key
    return encoded_dict

def scan_pcapng_for_encoded_ids(pcapng_file, encoded_dict):
    """
    Scan a pcapng file for IP packet IDs and check them against the dictionary of encoded ASCII values.
    
    :param pcapng_file: Path to the pcapng file
    :param encoded_dict: Dictionary of encoded ASCII values and their corresponding keys
    :return: A set of potential keys found in the pcap file.
    """
    packets = rdpcap(pcapng_file)
    potential_keys = set()
    
    for i, packet in enumerate(packets):
        if IP in packet:
            ip_id = packet[IP].id
            if ip_id in encoded_dict:
                key = encoded_dict[ip_id]
                potential_keys.add(key)
                print(f"Packet number: {i}")
                print(f"  IP ID: {ip_id}")
                print(f"  Encoded ASCII: {ip_id}")
                print(f"  Key used: {key}")
                print("-" * 30)  # Separator for readability
    
    return potential_keys

def decode_ip_ids(pcapng_file, key):
    """
    Decode IP IDs from a pcapng file into ASCII characters using the given key.
    
    :param pcapng_file: Path to the pcapng file
    :param key: The key used for decoding
    """
    packets = rdpcap(pcapng_file)
    decoded_chars = []
    
    for packet in packets:
        if IP in packet:
            ip_id = packet[IP].id
            # Reverse the encoding: id = ord(letter) * key
            if ip_id % key == 0:  # Check if IP ID is divisible by the key
                ord_letter = ip_id // key
                try:
                    decoded_char = chr(ord_letter)
                    decoded_chars.append(decoded_char)
                except ValueError:
                    # Skip values that do not correspond to valid ASCII characters
                    continue
    
    # Print the decoded ASCII characters
    decoded_message = ''.join(decoded_chars)
    if 'csawctf' in decoded_message:
        print(f"Found flag: {decoded_message} length: {len(decoded_message)}")
    else:
        print(f"No flag found: {decoded_message}")

# Example usage
message = "csawctf{"
encoded_dict = generate_encoded_ascii_dict(message)

# Replace 'your_pcapng_file.pcapng' with the path to your PCAPNG file
pcapng_file = 'chall.pcapng'

# Scan for potential keys
potential_keys = scan_pcapng_for_encoded_ids(pcapng_file, encoded_dict)

# Assuming key 55 is found based on your observation, let's proceed with that key
if 55 in potential_keys:
    decode_ip_ids(pcapng_file, key=55)
else:
    print("Key 55 not found in the pcapng file.")
