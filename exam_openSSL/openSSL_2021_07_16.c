/*
Implement, using the C programming language, the following function:
int envelop_MAC(RSA *rsa_keypair, char *message, int message_len, char *key, int keylenght, char* result);
which implements the following operations:
1) double_SHA256 of the concatenation of a message with a symmetric key;
2) RSA encrypt the result of the last step;
3) retums 0 in case of success, 1 in case of errors, and the result of the RSA encryption by reference.
In other words. the function has to implement the following transformation:
RSA_encrypt(public_key, SHA_256 ( SHA_256 ( message || key) |)
*/


#include <stdio.h>
#include <stdlib.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <string.h>
#include <openssl/pem.h>

int envelop_MAC(RSA *rsa_keypair, 
                char *message, 
                int message_len, 
                char *key, 
                int keylenght, 
                char* result);

int main(){



    return 0;
}

int envelop_MAC(RSA *rsa_keypair, char *message, int message_len, char *key, int keylenght, char* result){

    EVP_MD_CTX *md;

    int size = message_len + keylenght;
    char *concatenated = (char *)malloc(size*sizeof(char));
    
    int i=0;
    for(int j=0;j<message_len;j++){
        concatenated[i]=message[j];
        i++;
    }
    for(int j=0;j<keylenght;j++){
        concatenated[i]=key[j];
        i++;
    }

    md = EVP_MD_CTX_new();

    //Initialize the function hash
    EVP_DigestInit(md,EVP_sha256());

    //First round of HASH
    EVP_DigestUpdate(md,concatenated,strlen(concatenated));

    unsigned char md_value[20];
    int md_len;

    EVP_DigestFinal(md,md_value,&md_len);

    //Second round of HASH
    EVP_DigestUpdate(md,md_value,md_len);

    unsigned char md_value2[20];
    int md_len2;

    EVP_DigestFinal(md,md_value2,&md_len2);

    //Encyption phase
    int encrypted_data_len;
    unsigned char encypted_data[RSA_size(rsa_keypair)];

    encrypted_data_len = RSA_public_encrypt(strlen(concatenated)+1,concatenated,encypted_data,rsa_keypair,RSA_PKCS1_OAEP_PADDING);

    for(int i=0;i<encrypted_data_len;i++){
        fprintf(stdout,"%c",encypted_data[i]);
    }




    return 0;
}