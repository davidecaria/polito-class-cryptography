/*
Sketch the Diffie-Hellman key agreement protocol in C using the OpenSSL library.
Imagine you have a client CARL that starts communicating with a server SARA. CARL initiates the communication and proposes the public parameters.
Assume you have access to a set of high-level communication primitives that allow you to send and receive big numbers and to properly format them (e.g., based on a BIO), so that you don't have to think about the communication issues for this exercise.
void send_to_sara(BIGNUM b)
BIGNUM receive_from_sara()
void send_to_carlB/GNUM b)
BIGNUM receive_from_carl)
Finally answer the following question: what CARL and SARA have to do if they want to generate an AES-256 key?
*/

/*
The schema could be the following:

SARA 

1. generates: a,g,p
2. computes: A = g^a mod p
3. sends: g,p,A

CARL

1. generates: b
2. receives: g,p,A
3. computes: B = g^b mod p and K = A^b mod p
4. sends: B

SARA

4. receives: B
5. computes: K = B^a mod p 


now they have exchenged the keys
*/


#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#define SIZE 32 //Since we use AES-256

int main(){

    unsigned char key[SIZE];

    if(RAND_bytes(key,SIZE)!=1){
        fprintf(stdout,"Error generating the random key");
    }

    fprintf(stdout,"The key for AES-256 is: ");
    for(int i=0;i<SIZE;i++){
        fprintf(stdout,"%02x",key[i]);
    }


    return 1;
}