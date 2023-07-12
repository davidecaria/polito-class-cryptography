import sys
import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import socket

ecb_oracle_secret = "Here's my secret"
ecb_oracle_long_secret = "Here's my very long secret"
key = b'\x1e\x86\x114\x0b\x8d6k`\xb1\xdc\xb5\xa9\xc7,\xe8A\xe2\x1c\x0bk\x93Lc\xc0\xa9\xce\xae\xcc.z\xd2'

HOST = 'localhost'
PORT = 12345
DELTA_PORT = 101

###############################
def profile_for(email):
    #simulates a DB access to get user data
    email=email.replace('=','')
    email=email.replace('&','')

    dict = {}
    dict["email"] = email
    dict["UID"] = 10
    dict["role"] = "user"
    return dict

###############################
def encode_profile(dict):
    # generates the string from user data
    """
    :type dict: dictionary
    """
    s = ""
    i=0
    n = len(dict.keys())
    print(n)
    for key in dict.keys():
        s+=key+"="+str(dict[key])
        if i < (n-1):
            s+="&"
            i+=1
    return s

###############################

def encrypt_profile(encoded_profile):
    cipher = AES.new(key,AES.MODE_ECB)
    plaintext = pad(encoded_profile.encode(),AES.block_size)
    print(plaintext)
    return cipher.encrypt(plaintext)

###############################
def decrypt_msg(ciphertext):
    cipher = AES.new(key,AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext),AES.block_size)


if __name__ == '__main__':

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print('Socket created')

    try:
        s.bind((HOST, PORT))
    except socket.error as msg:
        print('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
        sys.exit()
    print('Socket bind complete')

    s.listen(10)
    print('Socket now listening')

    #wait to accept a connection - blocking call
    while 1:
        conn, addr = s.accept()
        print('A new encryption requested by ' + addr[0] + ':' + str(addr[1]))

        email = conn.recv(1024)
        cookie = encrypt_profile(encode_profile(profile_for(email.decode())))

        print("Cookie: " + encode_profile(profile_for(email.decode())))

        conn.send(cookie)
        conn.close()




    s.close()


