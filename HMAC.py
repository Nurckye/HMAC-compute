#!/usr/bin/env python3

# Author: Radu Nitescu
# Date: 26 November 2019
# Description: computes HMAC message authentication code

import hashlib
import string
import random

IPAD = 0x36 #54
OPAD = 0x5C #92

def generate_pseudo_random_key(message):
    return ''.join(random.choices(string.ascii_uppercase + 
                                   string.ascii_lowercase +
                                   string.digits,
                                   k = len(message))).encode()

def xor_message(message, key):
    res = []
    if len(message) != len(key):
        raise("Message and key have different lengths!")
    for index in range(len(message)):
        res.append(chr(message[index] ^ key[index]).encode())
    return b''.join(res)

#SHA265 HASH
def calculate_hash(data):
    return hashlib.sha256(data).digest()

def compute_padded_key(data, pad):
    res = []
    for byte in data:
        res.append(chr(byte ^ pad).encode())
    return b''.join(res) 

def compute_hmac(message, key):
    K1 = compute_padded_key(key, IPAD)
    K2 = compute_padded_key(key ,OPAD)
    return calculate_hash(K2 + calculate_hash(K1 + message))

def do_secure_stream(message, key):
    return xor_message(message, key) + \
           compute_hmac(message, key)

## Validation of the method ##
def recompute_original_messsage(encrypted, key):
    encrypted_message = encrypted[:-32]
    hmac = encrypted[-32:]
    original = xor_message(encrypted_message, key)
    if compute_hmac(original, key) != hmac:
        print("Original message ALTERED!")
    else:
        print("Original message was not altered!")
    print("Received message: " + original.decode())

def main():
    message = b"Hello world!"
    key = generate_pseudo_random_key(message)

    encoded_message = xor_message(message, key)
    message_to_send = do_secure_stream(message, key)

    recompute_original_messsage(message_to_send, key)

    #Altering the encrypted message with a 'w' character on 3rd position
    altered_message = list(message_to_send)
    altered_message[2] = ord('w')
    altered_message = bytearray(altered_message)

    recompute_original_messsage(altered_message, key)

if __name__ == '__main__':
    main()
