"""
Two users, Alice and Bob, who want to exchange messages encrypted with AES-128 in CBC mode, have agreed on a custom padding method. 

The padding function, if the last block contains the RESIDUE_BYTES, fills the block with the following operations:
RESIDUE_BYTES || (1 byte) length of RESIDUE_BYTES || the last 16-1-length of RESIDUE_BYTES of the IV

For instance, if the IV is (as hex string) "ABCDEF0123456789" and the RESIDUE_BYTES (i.e., the part of the last block to pad) are
"HELLO"
the last block is completed as:
"HELLO"+"5"+"0123456789"
• "5" because the length of RESIDUE_BYTES is 5 bytes,
• "0123456789" because these are the last 10 bytes (16-5-1) bytes of the IV
The code of the padding function is reported here:

def pad(msg, iv):
residue_len = len(msg) % AES.block_size

if residue_len == 0: # if the last block is full, add an entire block
    residue_len = AES.block size
padded_msg = msg
padded_msg += residue_len.to_bytes(1. byteorder='big' 

if residue_len <AES.block_size-1:
    bytes_to_add = AES.block_size - 1 - residue _len
padded_msg += iv[bytes_to_add:]
retur padded_msg

Bob has setup a server that receives IV and ciphertext and stores the decrypted messages locally. 
The server sends error messages to the sender in case of decryption issues. 
If the padding is incorrect. it returns the bytes b'wrongPAD'. 
To relevant part of the server's code is:
"""
from mysecrets import exam_july21_jv as iv
from mysecrets import exam_july21_ciphertext as ciphertext
from Crypto.Cipher import AES


def unpad(msg, iv):
    i = 0
    while msg[-i-1] == iv[-i-1]:
        i += 1
    if msg[-(i+1)] != (AES.block_size - i - 1):
        raise ValueError("Padding error")
    return msg[:-(i+1)]
    #
    # code here to open the socket
    #


def server_code():
    while 1:
        conn, addr = s.accept()
        print('A new padding test requested by ' +
              addr[0] + '.' + str(addr[11]))
        iv = conn.recv(AES.block_size)
        ciphertext = conn.rec(1024)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        try:
            c = cipher.decrypt(ciphertext)
            unpad(cipher.decrypt(ciphertext), iv)
        except ValueError:
            conn.send(b'wrongPAD')
            conn.close()
            continue

    conn.send(b'OKPAD')
    print('OK pad')


"""
You have sniffed a ciphertext that Alice has sent Bob, 
write a program in python to GUESS the last three bytes of the last block of the ciphertext, 
which can be accessed, together with the used IV as:
"""

# The best attacks to be performed here is the cbc padding oracle attack,
# this is beacuse the server is checking the padding and giving us a feedback about it

# The following code is a possible skeleton:

import math

def num_blocks(ciphertext, block_size):
    return math.ceil(len(ciphertext)/block_size)

#first block is 0
def get_nth_block(ciphertext, n, block_size):
    return ciphertext[(n)*block_size:(n+1)*block_size]

def get_n_blocks_from_m(ciphertext, n, m, block_size):
    return ciphertext[(m)*block_size:(m+n)*block_size]


def guess_byte(p,c,ciphertext,block_size):
    # p and c must have the same length
    padding_value = len(p)+1
    print("pad="+str(padding_value))
    n = num_blocks(ciphertext,block_size)
    print("n="+str(n))
    current_byte_index= len(ciphertext)-1 -block_size - len(p)
    print("current="+str(current_byte_index))

    # print(p)
    # print(c)
    plain = b'\x00'
    for i in range(0,256):
        # print(i)
        ca = bytearray()
        ca += ciphertext[:current_byte_index]
        ca += i.to_bytes(1,byteorder='big')

        # print(ca)
        for x in p:
            ca += (x ^ padding_value).to_bytes(1,byteorder='big')
        # print(ca)
        ca += get_nth_block(ciphertext,n-1,block_size)
        # print(ca)
        # print("          "+str(ciphertext))

        server = remote(HOST, PORT)
        server.send(iv)
        server.send(ca)
        response = server.recv(1024)

        # print(response)

        if response == b'OK':
            print("found",end=' ')
            print(i)

            p_prime = padding_value ^ i
            plain = bytes([p_prime ^ ciphertext[current_byte_index]])
            if plain == b'\x01': #this is not sufficient in the general case, onyl wokrs for the last byte and not always
                continue
            # print(p_prime)
            # print(ciphertext[current_byte_index])
            # print(p_prime ^ ciphertext[current_byte_index])
            c.insert(0,i)
            p.insert(0,p_prime)
            # print(p)
            # print(type(p_prime))
            # x= bytes([p_prime ^ ciphertext[current_byte_index]])
            # break


    return plain

def guess_byte_first_block(p, c, ciphertext, block_size):
    # p and c must have the same length
    padding_value = len(p)+1
    current_byte_index = block_size - len(p)-1

    for i in range(0, 256):
        # print(i)
        iv_ca = bytearray()
        iv_ca += iv[:current_byte_index]
        iv_ca += i.to_bytes(1, byteorder='big')

        for x in p:
            iv_ca += (x ^ padding_value).to_bytes(1, byteorder='big')

        server = remote(HOST, PORT)
        server.send(iv_ca)
        server.send(ciphertext)
        response = server.recv(1024)
        server.close()
        # print(response)

        if response == b'OK':
            print("found", end=' ')
            print(i)

            p_prime = padding_value ^ i
            c.insert(0, i)
            p.insert(0, p_prime)
            break

    return bytes([p_prime ^ iv[current_byte_index]])


if __name__ == '__main__':

    n = num_blocks(ciphertext, AES.block_size)
    plaintext = bytearray()
    for i in range(1, n):
        c = []
        p = []

        for j in range(0, AES.block_size):
            plaintext[0:0] = guess_byte(p, c, ciphertext, AES.block_size)
            print(plaintext)
        ciphertext = ciphertext[:-AES.block_size]

    print(len(ciphertext))
    c = []
    p = []
    for i in range(AES.block_size-2, AES.block_size):
        plaintext[0:0] = guess_byte_first_block(
            p, c, ciphertext, AES.block_size)
    # plaintext[0:0] = plain
    # plaintext[0:0] = guess_byte(p,c,ciphertext,AES.block_size)
    print(plaintext)
