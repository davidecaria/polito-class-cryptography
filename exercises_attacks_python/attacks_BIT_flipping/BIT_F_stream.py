####
# Thi version of the steam cipher bit flipping attack leverages many assumptions 
# about some information that may be available to the attacker
####

from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

if __name__ == '__main__':

    # We have a plaintext to be encrypted
    plaintext = b'New message to be encrypted'

    # Set up encryption with stream cipher
    key = get_random_bytes(32)
    nonce = get_random_bytes(12)
    cipher = ChaCha20.new(key=key,nonce=nonce)

    # Ecnryption of the message
    ciphertext = cipher.encrypt(plaintext=plaintext)

    print('Plaintext: ' + str(plaintext))
    print('Ciphertext: ' + str(ciphertext))

    # We assume that the attacker has the ciphertext and knows the position of a char in the plaintext
    index = plaintext.index(b'w')
    print('Index to modify: ' + str(index))

    # The attacker wants to change the w to a new value, for exaple 9
    new_value = b'9'
    new_int = ord(new_value) #This gets the ASCII code

    mask = ord(b'w') ^ new_int

    # We modify act as a man in the middle so we modify the ciphertext and send it to the receiver
    mod_ciphertext = bytearray(ciphertext)
    mod_ciphertext[index] = ciphertext[index] ^ mask

    # The receiver gets the new ciphertext (modified by the MITM)

    cipher_dec = ChaCha20.new(key=key,nonce=nonce)
    recovered_plaintext = cipher_dec.decrypt(mod_ciphertext)

    print('Recovered: ' + str(recovered_plaintext))



