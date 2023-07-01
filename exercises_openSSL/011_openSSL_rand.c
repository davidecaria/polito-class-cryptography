/*
Write a program in C that, using the OpenSSL library, generates two 128-bit random
strings. Then, it XOR them (bitwise/bytewise) and prints the result on the standard output as a hex
string.
*/


#include <stdio.h>
#include <stdlib.h>
#include <openssl/rand.h>

#define MAX 16

int main(){

    unsigned char string1[MAX];
    unsigned char string2[MAX];
    unsigned char string3[MAX];

    RAND_load_file("/dev/random",64);

    RAND_bytes(string1,MAX);
    RAND_bytes(string2,MAX);

    for(int i=0;i<MAX;i++){
        string3[i] = string1[i] ^ string2[i];
    }

    for(int i=0;i<MAX;i++){
        fprintf(stdout,"%02x",string3[i]);
    }
    


    return 0;
}