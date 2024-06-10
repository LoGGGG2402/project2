from scapy.all import *
from scapy.layers.inet import IP, TCP
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import os


# Function to generate RSA keys and save them to files
def generate_rsa_keys():
    key_gen = RSA.generate(1024)
    public_key = key_gen.publickey().export_key()
    private_key = key_gen.export_key()
    with open('public_key.pem', 'wb') as fi:
        fi.write(public_key)
    with open('private_key.pem', 'wb') as fi:
        fi.write(private_key)


# Generate RSA keys if they don't exist
if not (os.path.isfile('public_key.pem') and os.path.isfile('private_key.pem')):
    generate_rsa_keys()

# Import the private key
with open('private_key.pem', 'rb') as f:
    bin_private_key = f.read()

key = RSA.import_key(bin_private_key)
cipher = PKCS1_v1_5.new(key)


# Convert number to list of bits
def num_to_bits(num):
    return [int(i) for i in bin(num)[2:].zfill(8)]


# Convert list of bits to number
def bits_to_num(bits):
    return int("".join([str(i) for i in bits]), 2)


lst = {}
cipher_text = {}
payloads = {}


# Function to parse the received packets
def parse(pkt):
    global cipher_text
    global lst
    if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
        return

    flag = pkt[TCP].flags
    sport = pkt[TCP].sport
    sip = pkt[IP].src

    # Check if the packet is the one we are interested in
    if flag == 0x40 and sport == 123:
        dst_port = pkt[TCP].dport

        list_bits = num_to_bits(dst_port)

        payload = pkt[TCP].payload

        bytes_of_payload = bytes.fromhex(bytes_hex(payload).decode())

        if len(bytes_of_payload) % 16 == 0:
            try:
                msg = cipher.decrypt(cipher_text[sip], b'')
                # msg = cipher_text[sip]
                print(sip, msg)
                cipher_text[sip] = b''
                return
            except ValueError as e:
                print(e)
                print(cipher_text[sip])

        # if lst contains ip address
        if sip in lst:
            lst[sip].append(list_bits[len(bytes_of_payload) % 16])
            payloads[sip] += bytes_of_payload
        else:
            lst[sip] = [list_bits[len(bytes_of_payload) % 16]]
            payloads[sip] = bytes_of_payload

        if len(lst[sip]) == 8:
            num = bits_to_num(lst[sip])
            if sip not in cipher_text:
                cipher_text[sip] = bytes([num])
            else:
                cipher_text[sip] += bytes([num])
            lst[sip] = []


# Function to sniff packets
def server():
    sniff(iface="eth0", prn=parse)


# Run the server
if __name__ == "__main__":
    server()
