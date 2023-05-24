/*
Write a program that decrypts the following hex-string 

dfafe7eb90cdb23c149b9affd82e479d2d8ebafb7834d4b5d486ddaf5743e7a6ebdbdf7f006379ec960a0a20d2b83b61

with this parameters
key = ABCDEF01234567890123456789abcdef
iv = 01010101010101010101010101010101

The algorithm is not known, but it's either

aes-128-cbc, aes-256-cbc, or camellia-128-cbc
*/

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>


#define ENCRYPT 1
#define DECRYPT 0

int main()
{

    unsigned char key[] = "ABCDEF01234567890123456789abcdef";
    unsigned char iv[]  = "01010101010101010101010101010101";
    unsigned char ciphertext_hex[] = "dfafe7eb90cdb23c149b9affd82e479d2d8ebafb7834d4b5d486ddaf5743e7a6ebdbdf7f006379ec960a0a20d2b83b61";

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(ctx,EVP_camellia_128_cbc(), key, iv, DECRYPT);
    
    // convert hexstring into bytes
    int ciphertext_len = strlen(ciphertext_hex)/2;
    unsigned char ciphertext_binary[ciphertext_len];
    for(int i = 0; i < ciphertext_len;i++){
        sscanf(&ciphertext_hex[2*i],"%2hhx", &ciphertext_binary[i]);
    }
    for(int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext_binary[i]);
    printf("\n");


    unsigned char decrypted[ciphertext_len]; //may be larger than needed due to padding

    int update_len, final_len;
    int decrypted_len=0;
    EVP_CipherUpdate(ctx,decrypted,&update_len,ciphertext_binary,ciphertext_len);
    decrypted_len+=update_len;
    printf("update size: %d\n",decrypted_len);

    EVP_CipherFinal_ex(ctx,decrypted+decrypted_len,&final_len);
    decrypted_len+=final_len;

    EVP_CIPHER_CTX_free(ctx);

    printf("Plaintext lenght = %d\n",decrypted_len);
    for(int i = 0; i < decrypted_len; i++)
        printf("%2x", decrypted[i]);
    printf("\n");
    for(int i = 0; i < decrypted_len; i++)
        printf("%c", decrypted[i]);
    printf("\n");

    return 0;
}
