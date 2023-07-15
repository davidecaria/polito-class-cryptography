/*
The specification of the NONCENSE protocol includes the following operations:
1) generate a random 256-bit number, name it r1
2) generate a random 256-bit number, name it r2
3) obtain a key by XOR-ing the two random numbers r1 and r2, name it key_symm
4) generate an RSA keypair of at least 2048 bit modulus
5) Encrypt the generated RSA keypair using AES-256 with key_symm and obtain the payload.
Implement in C the protocol steps described above, make the proper decisions when the protocol omits information.
*/
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <string.h>

#include <stdlib.h>
#include <stdio.h>

#define SIZE 32 /* Since 256-bit is required */
#define ENCRYPT 1
#define DECRYPT 0

#define MAX_BUF 1024

int main() {

    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();

    /* Generating the random numbers */
    unsigned char rand_num_1[SIZE];
    unsigned char rand_num_2[SIZE];
    unsigned char sym_key[SIZE];

    RAND_bytes(rand_num_1, SIZE);
    RAND_bytes(rand_num_2, SIZE);

    /* XORing the two keys to get the symmetric one */
    for (int i = 0; i < SIZE; i++) {
        sym_key[i] = rand_num_1[i] ^ rand_num_2[i];
    }

    /* Generating an RSA key */
    RSA *rsa_keypair = NULL;
    BIGNUM *bne = NULL;

    int bits = 2048;
    unsigned long e = RSA_F4;

    bne = BN_new();
    if (!BN_set_word(bne, e)) {
        fprintf(stderr, "Error in generating the BN");
        exit(1);
    }

    rsa_keypair = RSA_new();
    if (!RSA_generate_key_ex(rsa_keypair, bits, bne, NULL)) {
        fprintf(stderr, "Error in generating the key");
        RSA_free(rsa_keypair);
        BN_free(bne);
        exit(1);
    }

    /* Encrypting the RSA key with the AES key */
    unsigned char iv[SIZE];
    RAND_bytes(iv, SIZE);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(ctx, EVP_aes_256_cbc(), sym_key, iv, ENCRYPT);

    unsigned char *rsa_keypair_bytes = NULL;
    int rsa_keypair_len = i2d_RSAPrivateKey(rsa_keypair, &rsa_keypair_bytes);
    if (rsa_keypair_len <= 0) {
        fprintf(stderr, "Failed to convert RSA keypair to bytes.\n");
        RSA_free(rsa_keypair);
        BN_free(bne);
        EVP_CIPHER_CTX_free(ctx);
        exit(1);
    }

    int update_len, final_len;
    int ciphertext_len = 0;
    unsigned char ciphertext[MAX_BUF];

    while(ciphertext_len < rsa_keypair_len){
        EVP_CipherUpdate(ctx, ciphertext, &update_len, rsa_keypair_bytes, strlen(rsa_keypair_bytes));
        ciphertext_len += update_len;
    }

    printf("%d %d\n",rsa_keypair_len,strlen(rsa_keypair_bytes));

    EVP_CipherFinal_ex(ctx, ciphertext + ciphertext_len, &final_len);
    ciphertext_len += final_len;

    EVP_CIPHER_CTX_free(ctx);

    /* Now everything is in the ciphertext and we can try to decrypt it */
    
    EVP_CIPHER_CTX *ctx_dec = EVP_CIPHER_CTX_new();
    EVP_CipherInit(ctx_dec, EVP_aes_256_cbc(), sym_key, iv, DECRYPT);

    unsigned char decrypted[MAX_BUF]; // may be larger than needed due to padding

    int update_len_dec, final_len_dec;
    int decrypted_len = 0;
    EVP_CipherUpdate(ctx_dec, decrypted, &update_len_dec, ciphertext, ciphertext_len);
    decrypted_len += update_len_dec;

    EVP_CipherFinal_ex(ctx_dec, decrypted + decrypted_len, &final_len_dec);
    decrypted_len += final_len_dec;

    EVP_CIPHER_CTX_free(ctx_dec);

    fprintf(stdout, "Original key: ");
    for (int i = 0; i < rsa_keypair_len; i++) {
        fprintf(stdout, "%02x", rsa_keypair_bytes[i]);
    }
    fprintf(stdout, "\n");

    fprintf(stdout, "Decrypted key: ");
    for (int i = 0; i < decrypted_len; i++) {
        fprintf(stdout, "%02x", decrypted[i]);
    }
    fprintf(stdout, "\n");

    RSA_free(rsa_keypair);
    BN_free(bne);
    free(rsa_keypair_bytes);

    return 0;
}
