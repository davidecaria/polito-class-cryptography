#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <string.h>

int main(){

    unsigned char plaintext[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    unsigned char key[] = "012345678912345";
    unsigned char iv[] = "012345678912345";

    OpenSSL_add_all_algorithms();

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_CipherInit(ctx,EVP_aes_128_cbc(),key,iv,1);

    unsigned char ciphertext[1024];

    int unpdate_len=0;
    int final_len=0;
    int ciphertext_len=0;
    EVP_CipherUpdate(ctx,ciphertext,&unpdate_len,plaintext,strlen(plaintext));
    ciphertext_len+=unpdate_len;
    EVP_CipherFinal_ex(ctx,ciphertext+unpdate_len,&final_len);
    ciphertext_len+=final_len;
    /* Decrypt */
    
    EVP_CipherInit(ctx,EVP_aes_128_cbc(),key,iv,0);


    unsigned char dectypted[1024];
    int decrypted_len=0;
    int final_len_dec=0;
    EVP_CipherUpdate(ctx,dectypted,&unpdate_len,ciphertext,ciphertext_len);
    decrypted_len+=unpdate_len;

    EVP_CipherFinal_ex(ctx,dectypted+unpdate_len,&final_len_dec);
    decrypted_len+=final_len_dec;

    for(int i=0;i<decrypted_len;i++){
        printf("%c",dectypted[i]);
    }
    printf("Hello");

    return 1;
}