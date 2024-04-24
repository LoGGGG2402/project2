
from scapy.all import *
from scapy.layers.inet import IP, TCP
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import random

# Destination IP address
dest = "127.0.0.1"

# Generate a random destination port
d_port = random.randint(0, 65535)

# Read the public key from file
with open('public_key.pem', 'rb') as f:
    bin_key = f.read()

# Import the public key
key = RSA.import_key(bin_key)
cipher = PKCS1_v1_5.new(key)


# Convert number to list of bits
def num_to_bits(num):
    return [int(i) for i in bin(num)[2:].zfill(8)]


# Convert list of bits to positions of 0s and 1s
def bits_to_pos(bits):
    list_0s = []
    list_1s = []
    for i in range(len(bits)):
        if bits[i] == 0:
            list_0s.append(i)
        else:
            list_1s.append(i)
    return list_0s, list_1s


# Craft the packet based on the input message length
def craft(message_length):
    character = ''.join(chr(random.randint(0, 255)) for _ in range(message_length))
    pkt = IP(dst=dest) / TCP(sport=123, dport=d_port, flags="E") / character
    return pkt


# Send the message
def client():
    while True:
        message = input('Enter your message: ')
        if message == 'exit':
            return

        ciphertext = cipher.encrypt(message.encode())

        for char in ciphertext:
            list_bits = num_to_bits(char)
            list_0s, list_1s = bits_to_pos(num_to_bits(d_port))
            for i in list_bits:
                if i == 0:
                    ind = list_0s[random.randint(0, len(list_0s) - 1)]
                else:
                    ind = list_1s[random.randint(0, len(list_1s) - 1)]
                pkt = craft(ind)
                send(pkt, verbose=False)

        # Send a special packet to indicate the end of the message
        pkt = IP(dst=dest) / TCP(sport=123, dport=4523, flags="E")
        send(pkt)


if __name__ == "__main__":
    client()
