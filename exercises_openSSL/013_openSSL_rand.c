/*
Writes a program in C that, using the OpenSSL library, randomly generates the private
key to be used for encrypting data with AES128 in CBC mode and the IV.
Pay attention to selecting the proper PRNG for both the “private” key and IV
*/

#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>

#define BUFFER 16

int main(){

    // To use a key and an IV for AES128 in CBC mode both have to be 128 bits (16 byte)


    unsigned char sk[BUFFER];
    unsigned char iv[BUFFER];


    //To add additional entropy
    if(RAND_poll() != 1){
        fprintf(stderr,"Error when performing RAND_poll");
        exit(EXIT_FAILURE);
    }

    if(RAND_bytes(sk,BUFFER) != 1){
        fprintf(stderr,"Error when generation a random key");
        exit(EXIT_FAILURE);
    }

    if(RAND_bytes(iv,BUFFER) != 1){
        fprintf(stderr,"Error generatation a random iv");
        exit(EXIT_FAILURE);
    }

    int i;
    fprintf(stdout,"Private key: ");
    for(i=0;i<BUFFER;i++){
        fprintf(stdout,"%02x",sk[i]);
    }
    fprintf(stdout,"\nInitialization vector: ");
    for(i=0;i<BUFFER;i++){
        fprintf(stdout,"%02x",iv[i]);
    }


    return 0;
}