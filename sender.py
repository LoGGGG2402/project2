from scapy.all import *
from scapy.layers.inet import IP, TCP
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import random
import re

# Destination IP address
dest = "192.168.48.131"

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
    for i in range(1, len(bits)):
        if bits[i] == 0:
            list_0s.append(i)
        else:
            list_1s.append(i)
    return list_0s, list_1s


# Craft the packet based on the input message length
def craft(file, start_pos, length, flag="E", payload="file"):
    if payload == "file":
        file.seek(start_pos)
        character = file.read(length)
        pkt = IP(dst=dest) / TCP(sport=123, dport=d_port, flags=flag) / character
    else:
        # create random payload
        character = ''.join(chr(random.randint(0, 255)) for _ in range(length))
        pkt = IP(dst=dest) / TCP(sport=123, dport=d_port, flags=flag) / character

    return pkt


# Send the message
def client():
    global dest
    destination = input('Enter the destination IP address: ')
    # check if the IP address is valid with regex ^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$
    if destination != '':
        if not re.match(r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$', destination):
            print('Invalid IP address')
            return
        dest = destination

    while True:
        message = input('Enter your message: ')
        if message == 'exit':
            return

        ciphertext = cipher.encrypt(message.encode())
        # ciphertext = message.encode()

        cipher_len = len(ciphertext) + 1

        file_name = input('Enter the file name: ')
        if file_name != '':
            # check if the file exists
            try:
                open(file_name, 'rb')
            except FileNotFoundError:
                print('File not found')
                return
            with open('Lec12.pdf', 'rb') as file:
                file_len = len(file.read())
                start_pos = 0
                packet_len = (((file_len // (cipher_len * 8)) - 16) // 1000) * 16
                print(ciphertext)
                for char in ciphertext:
                    list_bits = num_to_bits(char)
                    list_0s, list_1s = bits_to_pos(num_to_bits(d_port))
                    for i in list_bits:
                        if i == 0:
                            ind = list_0s[random.randint(0, len(list_0s) - 1)]
                        else:
                            ind = list_1s[random.randint(0, len(list_1s) - 1)]
                        pkt = craft(file, start_pos, packet_len + ind)
                        start_pos += packet_len + ind
                        send(pkt, verbose=False)

                # send special packet to indicate the end of the message
                pkt = craft(file, start_pos, packet_len)
                send(pkt, verbose=False)
                # close the file
                file.close()
        else:
            # create random packet length that is a multiple of 16
            packet_len = random.randint(1, 50) * 16
            for char in ciphertext:
                list_bits = num_to_bits(char)
                list_0s, list_1s = bits_to_pos(num_to_bits(d_port))
                for i in list_bits:
                    if i == 0:
                        ind = list_0s[random.randint(0, len(list_0s) - 1)]
                    else:
                        ind = list_1s[random.randint(0, len(list_1s) - 1)]
                    pkt = craft(None, 0, packet_len + ind, payload="random")
                    send(pkt, verbose=False)
            # send special packet to indicate the end of the message
            pkt = craft(None, 0, packet_len, payload="random")
            send(pkt, verbose=False)


if __name__ == "__main__":
    client()
