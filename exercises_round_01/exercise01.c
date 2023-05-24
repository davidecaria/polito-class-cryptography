/*
Write a program that computes the digest of the string
"Cryptography class 31-03-23"
using SHA3-384.
*/

#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

int main(){

    char message[] = "Cryptography class 31-03-23";

    //Allocate the contex
    EVP_MD_CTX *md;

    //Create a new contex
    md = EVP_MD_CTX_new();

    EVP_DigestInit(md,EVP_sha3_384());

    EVP_DigestUpdate(md,message,strlen(message));

    unsigned char outPut[20];
    int outLength;

    EVP_DigestFinal(md,outPut,&outLength);

    EVP_MD_CTX_free(md);

    for(int i=0;i<outLength;i++){
        printf("%02x",outPut[i]);
    }



    return 0;
}