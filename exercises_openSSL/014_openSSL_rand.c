/*
Using OpenSSL, generate two 32-bit integers (int), multiply them (modulo 2^32) and
print the result
*/

#include <stdlib.h>
#include <stdio.h>
#include <openssl/rand.h>

int main(){

    //Typically integers are 4 bytes long 

    int a,b;
    int result;

    //To add additional entropy
    if(RAND_poll() != 1){
        fprintf(stderr,"Error when performing RAND_poll");
        exit(EXIT_FAILURE);
    }

    RAND_bytes((unsigned char *)&a,sizeof(a));
    RAND_bytes((unsigned char *)&b,sizeof(b));

    result = ( a * b ) % (1UL << 32);

    printf("Random result: %d",result);

    return 0;
}