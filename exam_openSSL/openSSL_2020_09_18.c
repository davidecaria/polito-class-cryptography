/*
Alice wants to confidentially send Bob the content of a 1MB file through an insecure channel.
Write a program in C. using the OpenSSL library, which Alice can execute to send Bob the file.
Assume that:
1. the Bob's public key is stored into the RSA *bob_pubkey data structure;
2. the file to send is available in the FILE *file_in data structure;
3. Alice cannot establish TLS channels or resort to other protocols (i.e., only use the basic cryptographic algorithms you have seen during class);
4. you have access to a high-level communication primitive that sends and receives data and properly format them (e.g., based on a BIO). so that you don't have to think about the communication issues for this exercise
*/

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>

#define key_length 2048
#define BUFFER_SIZE 1024

RSA *bob_keypair;
FILE *file_in;
FILE *file_out;
char file_in_name[] = "file_in.txt";
char file_out_name[] = "file_out.txt";

int encrypt_file();
int decrypt_file();

int main()
{

    ERR_load_CRYPTO_strings();
    OpenSSL_add_all_algorithms();

    /* Generating the RSA key pair (not required for the ex)*/

    BIGNUM *bn_pub_exp = BN_new();
    BN_set_word(bn_pub_exp, RSA_F4);

    bob_keypair = RSA_new();
    if (!RSA_generate_key_ex(bob_keypair, key_length, bn_pub_exp, NULL))
    {
        fprintf(stderr, "Error generating the key");
        return 0;
    }

    /* Calling the function to encrypt the file */

    if (!encrypt_file())
    {
        fprintf(stderr, "Errors in the encryption of the file\n");
        return 0;
    }

    /* Now the file is enctrypted and can be sent */

    /* The correctness can be verified calling the decrypt function */

    if (!decrypt_file())
    {
        fprintf(stderr, "Error in decrypting the file\n");
        return 0;
    }

    return 1;
}

int encrypt_file()
{

    /* Opening the file to read and the file to write */

    if ((file_in = fopen(file_in_name, "r")) == NULL)
    {
        fprintf(stderr, "Error opening the input file\n");
        return 0;
    }

    if ((file_out = fopen(file_out_name, "w")) == NULL)
    {
        fprintf(stderr, "Error opening the output file\n");
        return 0;
    }

    /* Both file are open so I can encrypt */

    int encrypted_data_len;
    int num_reads;
    unsigned char enctrypted_data[RSA_size(bob_keypair)];
    unsigned char buffer_message[BUFFER_SIZE];

    fprintf(stdout, "Encryption started\n");

    while ((num_reads = fread(buffer_message, 1, BUFFER_SIZE, file_in)) > 0)
    {
        fprintf(stdout, "Ecrypting: %s\n", buffer_message);
        if ((encrypted_data_len = RSA_public_encrypt(strlen(buffer_message) + 1, buffer_message, enctrypted_data, bob_keypair, RSA_PKCS1_OAEP_PADDING)) == -1)
        {
            fprintf(stderr, "Error in enctrypting the line: %s\n", buffer_message);
            return 0;
        }
        fwrite(enctrypted_data, 1, RSA_size(bob_keypair), file_out);
    }

    fprintf(stdout, "Encryption finished\n");

    fclose(file_in);
    fclose(file_out);

    return 1;
}

int decrypt_file()
{

    if ((file_in = fopen(file_out_name, "r")) == NULL)
    {
        fprintf(stderr, "Error opening the input file\n");
        return 0;
    }

    int dencrypted_data_len;
    int num_reads;
    unsigned char enctrypted_data[RSA_size(bob_keypair)];
    unsigned char buffer_message[BUFFER_SIZE];

    fprintf(stdout, "Decryption started\n");

    while ((num_reads = fread(enctrypted_data, 1, RSA_size(bob_keypair), file_in)) > 0)
    {

        if ((dencrypted_data_len = RSA_private_decrypt(num_reads, enctrypted_data, buffer_message, bob_keypair, RSA_PKCS1_OAEP_PADDING)) == -1)
        {
            fprintf(stderr, "Error in denctrypting the line: %s\n", buffer_message);
            return 0;
        }
        fprintf(stdout, "Decrypting: %s\n", buffer_message);
    }

    fprintf(stdout, "Decryption finished\n");

    return 1;
}