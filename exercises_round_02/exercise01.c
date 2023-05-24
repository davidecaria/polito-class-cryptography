/*
Given the following 4 hexstring representation of integer numbers:
- a =0x 11111111111111111111111111111111
- b  = 0x22222222222222222222222222222222
- c = 0x3333
- d = 0x2341234123412341234

What is the result of

 (a+b) ^ c (mod d)  ?

Write the program in C using OpenSSL BIGNUMs.

HINT: Pay attention to pointers in the function prototype when looking at the OpenSSL help page.
*/

#include <openssl/bn.h>
#include <string.h>
int main(){

    char *a = "11111111111111111111111111111111\0";
    char *b = "22222222222222222222222222222222\0";
    char *c = "3333\0";
    char *d = "2341234123412341234\0";

    BIGNUM *b1 = BN_new();
    BIGNUM *b2 = BN_new();
    BIGNUM *b3 = BN_new();
    BIGNUM *b4 = BN_new();

    BN_hex2bn(&b1,a);
    BN_hex2bn(&b2,b);
    BN_hex2bn(&b3,c);
    BN_hex2bn(&b4,d);

    BIGNUM *temp = BN_new();
    BIGNUM *result = BN_new();
    BN_CTX *ctx=BN_CTX_new();
    BN_add(temp,b1,b2);

    BN_mod_exp(result,temp,b3,b4,ctx);
    BN_print_fp(stdout,result);
    
    return 0;
}