/*
*
*   Copyright (c) 2016 Matthew Mummert
*
*   This code is licensed under the MIT Open Source License:
*   https://opensource.org/licenses/MIT
*
*   Permission is hereby granted, free of charge, to any person obtaining
*   a copy of this software and associated documentation files (the "Software"),
*   to deal in the Software without restriction, including without limitation
*   the rights to use, copy, modify, merge, publish, distribute, sublicense,
*   and/or sell copies of the Software, and to permit persons to whom the Software
*   is furnished to do so, subject to the following conditions:
*
*   The above copyright notice and this permission notice shall be included in all
*   copies or substantial portions of the Software.
*
*   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
*   INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
*   PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
*   FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
*   OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
*   DEALINGS IN THE SOFTWARE.
*
*/

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

//bitmask for the program's mode
#define ENCRYPT_MODE        0x01    //Program is in encrypt mode
#define DECRYPT_MODE        0x02    //Program is in decrypt mode
#define KEYGEN_MODE         0x04    //Program is in key generation mode
#define OUTFILE_SPECIFIED   0x08    //The user has specified an output file
#define INFILE_SPECIFIED    0x10    //The user has specified an input file
#define PUBKEY_SPECIFIED    0x20    //The user has specified a public key file
#define SECKEY_SPECIFIED    0x40    //The user has specified a secret key file
#define SCRIPT_MODE         0x80    //The program will not output errors to the console, but will still return error codes

//Global bitmask for the program's options
uint32_t mode = 0;


#define MAX_STDIN_INPUT 32768

void dump(unsigned char* data, char* description, int length)
{
    int i;
    printf("%s\n", description);
    for(i = 0; i < length; i++)
    {
        printf("%.2X, ", data[i] & 0xFF);
    }
    printf("\n");
}

//This function will print error messages if we are not in SCRIPT_MODE
void print_error(char* error_message);

//This function parses command line arguments and sets the mode appropriately
//It returns 0xFFFFFFFF on error
uint32_t parse_commandline_args(int argc, char* argv[],
                                char* inputFile,
                                char* outputFile,
                                char* Public_Keyfile,
                                char* Secret_Keyfile);

//This function gets input from stdin
unsigned long long get_stdin(unsigned char* input, FILE* infile);

//This function generates user keyfiles. It returns -1 on failure
int keyFileGen(char* PK_filename, char* SK_filename);

//This function loads the Diffie-Hellman and Ed25519 public keys from the keyfile, and verifies the self-signature.
int loadPublicKeyFromFile(char* KeyFile, unsigned char* PublicCryptKey, unsigned char* PublicSignKey);

//This function loads the Diffie-Hellman and Ed25519 secret keys from the keyfile.
int loadSecretKeyFromFile(char* KeyFile, unsigned char* SecretCryptKey, unsigned char* SecretSignKey);


////////////////////////////////////////////////////////////////////
///////////////////Crypto Functions/////////////////////////////////
////////////////////////////////////////////////////////////////////


//This function locks a plaintext message. It first derives the symmetric key
//by performing a signature authenticated Diffie-Hellman key exchange, then
//encrypts and authenticates the plaintext with chacha20-poly1305
int lock_message(unsigned char* ciphertext,
            unsigned long long* ciphertext_len,
            unsigned char* plaintext,
            unsigned long long plaintext_len,
            unsigned char* Bob_publicKey,
            unsigned char* Alice_signKey);

//This function verifies and decrypts a message that was locked with 'lock_message()'
//First, it verifies the signed ephemeral Diffie-Hellman public key to verify the sender's
//identity. Then it verifies the poly1305 MAC and decrypts the chacha20 encrypted ciphertext.
//This function returns 0 on success, and returns -1 if cryptographic verification fails.
int unlock_message(unsigned char* plaintext,
                unsigned long long* plaintext_len,
                unsigned char* ciphertext,
                unsigned long long ciphertext_len,
                unsigned char* Alice_publicSignKey,
                unsigned char* Bob_secretKey);

int main(int argc, char* argv[])
{
    unsigned char Sender_publicKey[crypto_box_PUBLICKEYBYTES];
    unsigned char Sender_secretKey[crypto_box_SECRETKEYBYTES];
    unsigned char Recipient_publicKey[crypto_box_PUBLICKEYBYTES];
    unsigned char Recipient_secretKey[crypto_box_SECRETKEYBYTES];

    unsigned char Sender_publicSignKey[crypto_sign_PUBLICKEYBYTES];
    unsigned char Sender_secretSignKey[crypto_sign_SECRETKEYBYTES];

    unsigned char Recipient_publicSignKey[crypto_sign_PUBLICKEYBYTES];
    unsigned char Recipient_secretSignKey[crypto_sign_SECRETKEYBYTES];


    unsigned char input_data[40000];

    unsigned char* ciphertext;
    unsigned char* plaintext;

    char outputFile[128];
    FILE* outputFile_fp;

    char inputFile[128];
    FILE* inputFile_fp;

    char Secret_Keyfile[128];
    char Public_Keyfile[128];

    unsigned long long ciphertext_len = 0;
    unsigned long long plaintext_len = 0;

    int error_check;



    if(-1 == sodium_init())
    {
        printf("Initialization Error\n");
        return -1;
    }

    mode = parse_commandline_args(argc, argv, inputFile, outputFile, Public_Keyfile, Secret_Keyfile);

    //Check for errors in command line arguments
    if(0xFFFFFFFF == mode)
    {
        //Error with command line arguments
        //Return error code 2
        print_error("Error with command line arguments");
        return 2;
    }



    //Encrypt Mode
    if((ENCRYPT_MODE & mode) == ENCRYPT_MODE)
    {
        error_check = loadPublicKeyFromFile(Public_Keyfile, Recipient_publicKey, Recipient_publicSignKey);

        //Check for proper file opening and reading
        if(error_check == 3)
        {
            //Error with opening and/or reading file
            //Return error code 3
            print_error("Error opening and/or reading public keyfile");
            sodium_memzero(Sender_publicKey, sizeof(Sender_publicKey));
            sodium_memzero(Sender_secretKey, sizeof(Sender_secretKey));
            sodium_memzero(Recipient_publicKey, sizeof(Recipient_publicKey));
            sodium_memzero(Recipient_secretKey, sizeof(Recipient_secretKey));
            sodium_memzero(Sender_publicSignKey, sizeof(Sender_publicSignKey));
            sodium_memzero(Sender_secretSignKey, sizeof(Sender_secretSignKey));
            sodium_memzero(Recipient_publicSignKey, sizeof(Recipient_publicSignKey));
            sodium_memzero(Recipient_secretSignKey, sizeof(Recipient_secretSignKey));
            sodium_memzero(input_data, sizeof(input_data));
            return 3;
        }

        //Check for proper self-signature on public key
        if(error_check == -1)
        {
            //self-signature on public keyfile is invalid
            //Return error code 4
            print_error("Self-signature on public keyfile is invalid");
            sodium_memzero(Sender_publicKey, sizeof(Sender_publicKey));
            sodium_memzero(Sender_secretKey, sizeof(Sender_secretKey));
            sodium_memzero(Recipient_publicKey, sizeof(Recipient_publicKey));
            sodium_memzero(Recipient_secretKey, sizeof(Recipient_secretKey));
            sodium_memzero(Sender_publicSignKey, sizeof(Sender_publicSignKey));
            sodium_memzero(Sender_secretSignKey, sizeof(Sender_secretSignKey));
            sodium_memzero(Recipient_publicSignKey, sizeof(Recipient_publicSignKey));
            sodium_memzero(Recipient_secretSignKey, sizeof(Recipient_secretSignKey));
            sodium_memzero(input_data, sizeof(input_data));
            return 4;
        }

        error_check = loadSecretKeyFromFile(Secret_Keyfile, Sender_secretKey, Sender_secretSignKey);

        //Check for proper file opening and reading
        if(error_check == 3)
        {
            //Error with opening and/or reading file
            //Return error code 3
            print_error("Error opening and/or reading secret keyfile\n");
            sodium_memzero(Sender_publicKey, sizeof(Sender_publicKey));
            sodium_memzero(Sender_secretKey, sizeof(Sender_secretKey));
            sodium_memzero(Recipient_publicKey, sizeof(Recipient_publicKey));
            sodium_memzero(Recipient_secretKey, sizeof(Recipient_secretKey));
            sodium_memzero(Sender_publicSignKey, sizeof(Sender_publicSignKey));
            sodium_memzero(Sender_secretSignKey, sizeof(Sender_secretSignKey));
            sodium_memzero(Recipient_publicSignKey, sizeof(Recipient_publicSignKey));
            sodium_memzero(Recipient_secretSignKey, sizeof(Recipient_secretSignKey));
            sodium_memzero(input_data, sizeof(input_data));
            return 3;
        }

        //If an input file is specified, use it
        if((INFILE_SPECIFIED & mode) == INFILE_SPECIFIED)
        {


            inputFile_fp = fopen(inputFile, "rb");

            if(NULL == inputFile_fp)
            {
                print_error("Error with input file\n");
                sodium_memzero(Sender_publicKey, sizeof(Sender_publicKey));
                sodium_memzero(Sender_secretKey, sizeof(Sender_secretKey));
                sodium_memzero(Recipient_publicKey, sizeof(Recipient_publicKey));
                sodium_memzero(Recipient_secretKey, sizeof(Recipient_secretKey));
                sodium_memzero(Sender_publicSignKey, sizeof(Sender_publicSignKey));
                sodium_memzero(Sender_secretSignKey, sizeof(Sender_secretSignKey));
                sodium_memzero(Recipient_publicSignKey, sizeof(Recipient_publicSignKey));
                sodium_memzero(Recipient_secretSignKey, sizeof(Recipient_secretSignKey));
                sodium_memzero(input_data, sizeof(input_data));
                return 3;
            }

            //Get the size of the input file
            fseek(inputFile_fp, 0, SEEK_END);       //Seek to the end of the file
            plaintext_len = ftell(inputFile_fp);    //Check the position of the file, which equals the size of the file in bytes
            fseek(inputFile_fp, 0, SEEK_SET);       //Seek back to the beginning of the file

            //Reserve some memory on the heap for the plaintext
            plaintext = malloc(plaintext_len + 1);

            //Check to make sure memory allocation was successful
            if(NULL == plaintext)
            {
                //Error reserving memory
                //Return error code 5
                print_error("Error reserving memory for the plaintext");
                sodium_memzero(Sender_publicKey, sizeof(Sender_publicKey));
                sodium_memzero(Sender_secretKey, sizeof(Sender_secretKey));
                sodium_memzero(Recipient_publicKey, sizeof(Recipient_publicKey));
                sodium_memzero(Recipient_secretKey, sizeof(Recipient_secretKey));
                sodium_memzero(Sender_publicSignKey, sizeof(Sender_publicSignKey));
                sodium_memzero(Sender_secretSignKey, sizeof(Sender_secretSignKey));
                sodium_memzero(Recipient_publicSignKey, sizeof(Recipient_publicSignKey));
                sodium_memzero(Recipient_secretSignKey, sizeof(Recipient_secretSignKey));
                sodium_memzero(input_data, sizeof(input_data));
                return 5;
            }

            fread(plaintext, sizeof(char), plaintext_len, inputFile_fp);
            fclose(inputFile_fp);
        }

        //else get the input from stdin
        else
        {
            plaintext_len = get_stdin(input_data, stdin);

            //Reserve some memory on the heap for the plaintext
            plaintext = malloc(plaintext_len + 1);

            //Check to make sure memory allocation was successful
            if(NULL == plaintext)
            {
                //Error reserving memory
                //Return error code 5
                sodium_memzero(Sender_publicKey, sizeof(Sender_publicKey));
                sodium_memzero(Sender_secretKey, sizeof(Sender_secretKey));
                sodium_memzero(Recipient_publicKey, sizeof(Recipient_publicKey));
                sodium_memzero(Recipient_secretKey, sizeof(Recipient_secretKey));
                sodium_memzero(Sender_publicSignKey, sizeof(Sender_publicSignKey));
                sodium_memzero(Sender_secretSignKey, sizeof(Sender_secretSignKey));
                sodium_memzero(Recipient_publicSignKey, sizeof(Recipient_publicSignKey));
                sodium_memzero(Recipient_secretSignKey, sizeof(Recipient_secretSignKey));
                sodium_memzero(input_data, sizeof(input_data));
                return 5;
            }

            memcpy(plaintext, input_data, plaintext_len);
            sodium_memzero(input_data, sizeof(input_data));

        }

        //Reserve some memory on the heap for the ciphertext. We need 112 bytes more than the plaintext for the ciphertext
        ciphertext = malloc(plaintext_len + crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES + crypto_aead_chacha20poly1305_IETF_ABYTES);

        //Check to make sure memory allocation was successful
        if(NULL == ciphertext)
        {
            //Error reserving memory
            //Return error code 5
            print_error("Error reserving memory for the ciphertext");
            sodium_memzero(plaintext, plaintext_len);
            sodium_memzero(Sender_publicKey, sizeof(Sender_publicKey));
            sodium_memzero(Sender_secretKey, sizeof(Sender_secretKey));
            sodium_memzero(Recipient_publicKey, sizeof(Recipient_publicKey));
            sodium_memzero(Recipient_secretKey, sizeof(Recipient_secretKey));
            sodium_memzero(Sender_publicSignKey, sizeof(Sender_publicSignKey));
            sodium_memzero(Sender_secretSignKey, sizeof(Sender_secretSignKey));
            sodium_memzero(Recipient_publicSignKey, sizeof(Recipient_publicSignKey));
            sodium_memzero(Recipient_secretSignKey, sizeof(Recipient_secretSignKey));
            sodium_memzero(input_data, sizeof(input_data));
            free(plaintext);
            return 5;
        }


        //Sign, encrypt, and authenticate the plaintext
        lock_message(ciphertext, &ciphertext_len, plaintext, plaintext_len, Recipient_publicKey, Sender_secretSignKey);

        //If an output file is specified, write to it
        if((OUTFILE_SPECIFIED & mode) == OUTFILE_SPECIFIED)
        {

            outputFile_fp = fopen(outputFile, "wb");

            if(NULL == outputFile_fp)
            {
                //Error opening file. Free memory and return error code 3
                print_error("Error with output file");
                sodium_memzero(plaintext, plaintext_len);
                sodium_memzero(ciphertext, ciphertext_len);
                sodium_memzero(Sender_publicKey, sizeof(Sender_publicKey));
                sodium_memzero(Sender_secretKey, sizeof(Sender_secretKey));
                sodium_memzero(Recipient_publicKey, sizeof(Recipient_publicKey));
                sodium_memzero(Recipient_secretKey, sizeof(Recipient_secretKey));
                sodium_memzero(Sender_publicSignKey, sizeof(Sender_publicSignKey));
                sodium_memzero(Sender_secretSignKey, sizeof(Sender_secretSignKey));
                sodium_memzero(Recipient_publicSignKey, sizeof(Recipient_publicSignKey));
                sodium_memzero(Recipient_secretSignKey, sizeof(Recipient_secretSignKey));
                sodium_memzero(input_data, sizeof(input_data));
                free(plaintext);
                free(ciphertext);
                return 3;
            }

            fwrite(ciphertext, sizeof(char), ciphertext_len, outputFile_fp);
            fclose(outputFile_fp);
        }

        //Else, print to stdout
        else
        {
            fwrite(ciphertext, sizeof(char), ciphertext_len, stdout);

        }

        sodium_memzero(plaintext, plaintext_len);
        sodium_memzero(ciphertext, ciphertext_len);
        free(plaintext);
        free(ciphertext);


    }

    //Decrypt Mode
    if((DECRYPT_MODE & mode) == DECRYPT_MODE)
    {
        error_check = loadPublicKeyFromFile(Public_Keyfile, Sender_publicKey, Sender_publicSignKey);

        //Check for proper file opening and reading
        if(error_check == 3)
        {
            //Error with opening and/or reading file
            //Return error code 3
            print_error("Error opening and/or reading public keyfile");
            sodium_memzero(Sender_publicKey, sizeof(Sender_publicKey));
            sodium_memzero(Sender_secretKey, sizeof(Sender_secretKey));
            sodium_memzero(Recipient_publicKey, sizeof(Recipient_publicKey));
            sodium_memzero(Recipient_secretKey, sizeof(Recipient_secretKey));
            sodium_memzero(Sender_publicSignKey, sizeof(Sender_publicSignKey));
            sodium_memzero(Sender_secretSignKey, sizeof(Sender_secretSignKey));
            sodium_memzero(Recipient_publicSignKey, sizeof(Recipient_publicSignKey));
            sodium_memzero(Recipient_secretSignKey, sizeof(Recipient_secretSignKey));
            sodium_memzero(input_data, sizeof(input_data));
            return 3;
        }

        //Check for proper self-signature on public key
        if(error_check == -1)
        {
            //self-signature on public keyfile is invalid
            //Return error code 4
            print_error("Self-signature on public keyfile is invalid");
            sodium_memzero(Sender_publicKey, sizeof(Sender_publicKey));
            sodium_memzero(Sender_secretKey, sizeof(Sender_secretKey));
            sodium_memzero(Recipient_publicKey, sizeof(Recipient_publicKey));
            sodium_memzero(Recipient_secretKey, sizeof(Recipient_secretKey));
            sodium_memzero(Sender_publicSignKey, sizeof(Sender_publicSignKey));
            sodium_memzero(Sender_secretSignKey, sizeof(Sender_secretSignKey));
            sodium_memzero(Recipient_publicSignKey, sizeof(Recipient_publicSignKey));
            sodium_memzero(Recipient_secretSignKey, sizeof(Recipient_secretSignKey));
            sodium_memzero(input_data, sizeof(input_data));
            return 4;
        }

        error_check = loadSecretKeyFromFile(Secret_Keyfile, Recipient_secretKey, Recipient_secretSignKey);

        //Check for proper file opening and reading
        if(error_check == 3)
        {
            //Error with opening and/or reading file
            //Return error code 3
            print_error("Error opening and/or reading secret keyfile\n");
            sodium_memzero(Sender_publicKey, sizeof(Sender_publicKey));
            sodium_memzero(Sender_secretKey, sizeof(Sender_secretKey));
            sodium_memzero(Recipient_publicKey, sizeof(Recipient_publicKey));
            sodium_memzero(Recipient_secretKey, sizeof(Recipient_secretKey));
            sodium_memzero(Sender_publicSignKey, sizeof(Sender_publicSignKey));
            sodium_memzero(Sender_secretSignKey, sizeof(Sender_secretSignKey));
            sodium_memzero(Recipient_publicSignKey, sizeof(Recipient_publicSignKey));
            sodium_memzero(Recipient_secretSignKey, sizeof(Recipient_secretSignKey));
            sodium_memzero(input_data, sizeof(input_data));
            return 3;
        }

        //If an input file is specified, use it
        if((INFILE_SPECIFIED & mode) == INFILE_SPECIFIED)
        {
            inputFile_fp = fopen(inputFile, "rb");

            if(NULL == inputFile_fp)
            {
                print_error("Error with input file\n");
                sodium_memzero(Sender_publicKey, sizeof(Sender_publicKey));
                sodium_memzero(Sender_secretKey, sizeof(Sender_secretKey));
                sodium_memzero(Recipient_publicKey, sizeof(Recipient_publicKey));
                sodium_memzero(Recipient_secretKey, sizeof(Recipient_secretKey));
                sodium_memzero(Sender_publicSignKey, sizeof(Sender_publicSignKey));
                sodium_memzero(Sender_secretSignKey, sizeof(Sender_secretSignKey));
                sodium_memzero(Recipient_publicSignKey, sizeof(Recipient_publicSignKey));
                sodium_memzero(Recipient_secretSignKey, sizeof(Recipient_secretSignKey));
                sodium_memzero(input_data, sizeof(input_data));
                return 3;
            }

            //Get size of input file
            fseek(inputFile_fp, 0, SEEK_END);       //Seek to the end of the file
            ciphertext_len = ftell(inputFile_fp);   //Check the position of the file, which equals the size of the file in bytes
            fseek(inputFile_fp, 0, SEEK_SET);       //Seek back to the beginning of the file

            //Reserve some memory on the heap for the ciphertext.
            ciphertext = malloc(ciphertext_len + 1);

            //Check to make sure memory allocation was successful
            if(NULL == ciphertext)
            {
                //Error reserving memory
                //Return error code 5
                print_error("Error reserving memory for the ciphertext");
                sodium_memzero(Sender_publicKey, sizeof(Sender_publicKey));
                sodium_memzero(Sender_secretKey, sizeof(Sender_secretKey));
                sodium_memzero(Recipient_publicKey, sizeof(Recipient_publicKey));
                sodium_memzero(Recipient_secretKey, sizeof(Recipient_secretKey));
                sodium_memzero(Sender_publicSignKey, sizeof(Sender_publicSignKey));
                sodium_memzero(Sender_secretSignKey, sizeof(Sender_secretSignKey));
                sodium_memzero(Recipient_publicSignKey, sizeof(Recipient_publicSignKey));
                sodium_memzero(Recipient_secretSignKey, sizeof(Recipient_secretSignKey));
                sodium_memzero(input_data, sizeof(input_data));
                return 5;
            }

            fread(ciphertext, sizeof(char), ciphertext_len, inputFile_fp);
            fclose(inputFile_fp);

        }

        //Else use stdin
        else
        {
            ciphertext_len = get_stdin(input_data, stdin);

            //Reserve some memory on the heap for the ciphertext.
            ciphertext = malloc(ciphertext_len + 1);

            //Check to make sure memory allocation was successful
            if(NULL == ciphertext)
            {
                //Error reserving memory
                //Return error code 5
                print_error("Error reserving memory for the ciphertext");
                sodium_memzero(Sender_publicKey, sizeof(Sender_publicKey));
                sodium_memzero(Sender_secretKey, sizeof(Sender_secretKey));
                sodium_memzero(Recipient_publicKey, sizeof(Recipient_publicKey));
                sodium_memzero(Recipient_secretKey, sizeof(Recipient_secretKey));
                sodium_memzero(Sender_publicSignKey, sizeof(Sender_publicSignKey));
                sodium_memzero(Sender_secretSignKey, sizeof(Sender_secretSignKey));
                sodium_memzero(Recipient_publicSignKey, sizeof(Recipient_publicSignKey));
                sodium_memzero(Recipient_secretSignKey, sizeof(Recipient_secretSignKey));
                sodium_memzero(input_data, sizeof(input_data));
                return 5;
            }

            memcpy(ciphertext, input_data, ciphertext_len);
            sodium_memzero(input_data, sizeof(input_data));
        }

        //Allocate some memory on the heap for the plaintext
        plaintext = malloc(ciphertext_len + 1);

        //Check to make sure memory allocation was successful
        if(NULL == plaintext)
        {
            //Error reserving memory
            //Return error code 5
            print_error("Error reserving memory for the plaintext");
            sodium_memzero(ciphertext, ciphertext_len);
            sodium_memzero(Sender_publicKey, sizeof(Sender_publicKey));
            sodium_memzero(Sender_secretKey, sizeof(Sender_secretKey));
            sodium_memzero(Recipient_publicKey, sizeof(Recipient_publicKey));
            sodium_memzero(Recipient_secretKey, sizeof(Recipient_secretKey));
            sodium_memzero(Sender_publicSignKey, sizeof(Sender_publicSignKey));
            sodium_memzero(Sender_secretSignKey, sizeof(Sender_secretSignKey));
            sodium_memzero(Recipient_publicSignKey, sizeof(Recipient_publicSignKey));
            sodium_memzero(Recipient_secretSignKey, sizeof(Recipient_secretSignKey));
            sodium_memzero(input_data, sizeof(input_data));
            free(ciphertext);
            return 5;
        }

        //Now we verify and decrypt the sender's message
        error_check = unlock_message(plaintext, &plaintext_len, ciphertext, ciphertext_len, Sender_publicSignKey, Recipient_secretKey);

        //Verify there was no signature or MAC verification failures
        if(-1 == error_check)
        {
            //Signature or MAC verification failure
            //Return error code 2
            print_error("Cryptographic Verification failed");
            sodium_memzero(plaintext, plaintext_len);
            sodium_memzero(ciphertext, ciphertext_len);
            sodium_memzero(Sender_publicKey, sizeof(Sender_publicKey));
            sodium_memzero(Sender_secretKey, sizeof(Sender_secretKey));
            sodium_memzero(Recipient_publicKey, sizeof(Recipient_publicKey));
            sodium_memzero(Recipient_secretKey, sizeof(Recipient_secretKey));
            sodium_memzero(Sender_publicSignKey, sizeof(Sender_publicSignKey));
            sodium_memzero(Sender_secretSignKey, sizeof(Sender_secretSignKey));
            sodium_memzero(Recipient_publicSignKey, sizeof(Recipient_publicSignKey));
            sodium_memzero(Recipient_secretSignKey, sizeof(Recipient_secretSignKey));
            sodium_memzero(input_data, sizeof(input_data));
            free(plaintext);
            free(ciphertext);
            return 1;
        }

        //If an output file is specified, write to it
        if((OUTFILE_SPECIFIED & mode) == OUTFILE_SPECIFIED)
        {
            outputFile_fp = fopen(outputFile, "wb");

            if(NULL == outputFile_fp)
            {
                //Error opening output file
                //Free memory and return error code 3
                print_error("Error with output file\n");
                sodium_memzero(plaintext, plaintext_len);
                sodium_memzero(ciphertext, ciphertext_len);
                sodium_memzero(Sender_publicKey, sizeof(Sender_publicKey));
                sodium_memzero(Sender_secretKey, sizeof(Sender_secretKey));
                sodium_memzero(Recipient_publicKey, sizeof(Recipient_publicKey));
                sodium_memzero(Recipient_secretKey, sizeof(Recipient_secretKey));
                sodium_memzero(Sender_publicSignKey, sizeof(Sender_publicSignKey));
                sodium_memzero(Sender_secretSignKey, sizeof(Sender_secretSignKey));
                sodium_memzero(Recipient_publicSignKey, sizeof(Recipient_publicSignKey));
                sodium_memzero(Recipient_secretSignKey, sizeof(Recipient_secretSignKey));
                sodium_memzero(input_data, sizeof(input_data));
                free(plaintext);
                free(ciphertext);
                return 3;
            }

            fwrite(plaintext, sizeof(char), plaintext_len, outputFile_fp);
            fclose(outputFile_fp);

        }

        //Else, print to stdout
        else
        {
            fwrite(plaintext, sizeof(char), plaintext_len, stdout);

        }


        sodium_memzero(plaintext, plaintext_len);
        sodium_memzero(ciphertext, ciphertext_len);
        free(plaintext);
        free(ciphertext);
    }

    //Key Generation Mode
    if((KEYGEN_MODE & mode) == KEYGEN_MODE)
    {
        //If a public and secret keyfile name has been specified, then use those filenames
        if( (((PUBKEY_SPECIFIED & mode) == PUBKEY_SPECIFIED)) && (((SECKEY_SPECIFIED & mode) == SECKEY_SPECIFIED)) )
        {
            error_check = keyFileGen(Public_Keyfile, Secret_Keyfile);
            if(0 != error_check)
            {
                print_error("Error generating key files");
                sodium_memzero(Sender_publicKey, sizeof(Sender_publicKey));
                sodium_memzero(Sender_secretKey, sizeof(Sender_secretKey));
                sodium_memzero(Recipient_publicKey, sizeof(Recipient_publicKey));
                sodium_memzero(Recipient_secretKey, sizeof(Recipient_secretKey));
                sodium_memzero(Sender_publicSignKey, sizeof(Sender_publicSignKey));
                sodium_memzero(Sender_secretSignKey, sizeof(Sender_secretSignKey));
                sodium_memzero(Recipient_publicSignKey, sizeof(Recipient_publicSignKey));
                sodium_memzero(Recipient_secretSignKey, sizeof(Recipient_secretSignKey));
                sodium_memzero(input_data, sizeof(input_data));
                return 3;
            }
        }

        //else, use the default filenames "MyKey.pub" and "MyKey.sec"
        else
        {
            error_check = keyFileGen("MyKey.pub", "MyKey.sec");
            if(0 != error_check)
            {
                print_error("Error generating key files");
                sodium_memzero(Sender_publicKey, sizeof(Sender_publicKey));
                sodium_memzero(Sender_secretKey, sizeof(Sender_secretKey));
                sodium_memzero(Recipient_publicKey, sizeof(Recipient_publicKey));
                sodium_memzero(Recipient_secretKey, sizeof(Recipient_secretKey));
                sodium_memzero(Sender_publicSignKey, sizeof(Sender_publicSignKey));
                sodium_memzero(Sender_secretSignKey, sizeof(Sender_secretSignKey));
                sodium_memzero(Recipient_publicSignKey, sizeof(Recipient_publicSignKey));
                sodium_memzero(Recipient_secretSignKey, sizeof(Recipient_secretSignKey));
                sodium_memzero(input_data, sizeof(input_data));
                return 3;
            }
        }


    }

    //Zero all cryptographic variables
    sodium_memzero(Sender_publicKey, sizeof(Sender_publicKey));
    sodium_memzero(Sender_secretKey, sizeof(Sender_secretKey));
    sodium_memzero(Recipient_publicKey, sizeof(Recipient_publicKey));
    sodium_memzero(Recipient_secretKey, sizeof(Recipient_secretKey));
    sodium_memzero(Sender_publicSignKey, sizeof(Sender_publicSignKey));
    sodium_memzero(Sender_secretSignKey, sizeof(Sender_secretSignKey));
    sodium_memzero(Recipient_publicSignKey, sizeof(Recipient_publicSignKey));
    sodium_memzero(Recipient_secretSignKey, sizeof(Recipient_secretSignKey));
    sodium_memzero(input_data, sizeof(input_data));



    return 0;
}


//This function will print error messages if we are not in SCRIPT_MODE
void print_error(char* error_message)
{
    //Check to see if we are in script mode
    if((SCRIPT_MODE & mode) == SCRIPT_MODE)
    {
        //We are in script mode, return from the function
        return;
    }

    else
    {
        printf("%s\n", error_message);
    }

    return;
}



//This function parses command line arguments and sets the mode bitmask appropriately
//It returns 0xFFFFFFFF on error
uint32_t parse_commandline_args(int argc, char* argv[],
                                char* inputFile,
                                char* outputFile,
                                char* Public_Keyfile,
                                char* Secret_Keyfile)
{
    int i;
    uint32_t mask = 0;
    uint32_t temp = 0;

    mask = 0;

    //Check to see if user passed in any command line arguments
    if(1 == argc)
    {
        print_error("ERROR: No command line arguments passed in");
        return 0xFFFFFFFF;
    }

    //Check for version command
    if(strncmp("--version", argv[1], 9) == 0)
    {
        print_error("lightcrypt: 1.0");
        return 0;
    }

    //Before doing anything, we must cycle through all the command line arguments to check if we are in script mode
    for(i = 1; i < argc; i++)
    {
        //We are in script mode. The program will not output any messages to the console
        if(strncmp("--script", argv[i], 8) == 0)
        {
            mask |= SCRIPT_MODE;
            mode = mask;
        }
    }

    //Now we parse the rest of the arguments
    for(i = 1; i < argc; i++)
    {

        //Encrypt mode
        if(strncmp("-e", argv[i], 2) == 0)
        {
            mask |= ENCRYPT_MODE;
        }

        //Decrypt mode
        else if(strncmp("-d", argv[i], 2) == 0)
        {
            mask |= DECRYPT_MODE;
        }

        //Keygen mode
        else if(strncmp("-keygen", argv[i], 7) == 0)
        {
            mask |= KEYGEN_MODE;
        }

        //Output file is specified with '-o' and the next argument will be the name of the outfile
        //If no output file is specified, the program will output to stdout
        else if(strncmp("-o", argv[i], 2) == 0)
        {
            if(NULL != argv[i + 1])
            {
                strncpy(outputFile, argv[i + 1], 100);
                mask |= OUTFILE_SPECIFIED;

            }

            else
            {
                //User failed to specify an output file after passing "-o" as an argument
                print_error("No output file specified after -o argument");
                return 0xFFFFFFFF;
            }

            //prevent the loop from examining the next command line argument.
            //We don't need to because that's the name of the output file
            i++;


        }

        //Input file is specified with '-in' and the next argument will be the name of the infile
        //If no input file is specified, the program will read from stdin
        else if(strncmp("-in", argv[i], 3) == 0)
        {

            if(NULL != argv[i + 1])
            {
                strncpy(inputFile, argv[i + 1], 100);
                mask |= INFILE_SPECIFIED;

            }

            else
            {
                //User failed to specify an output file after passing "-in" as an argument
                print_error("No input file specified after -in argument");
                return 0xFFFFFFFF;
            }

            //prevent the loop from examining the next command line argument.
            //We don't need to because that's the name of the input file
            i++;


        }

        //Public Key file is specified with "-pub" and the next argument will be the name of the public key file
        else if(strncmp("-pub", argv[i], 4) == 0)
        {
            if(NULL != argv[i + 1])
            {
                strncpy(Public_Keyfile, argv[i + 1], 100);
                mask |= PUBKEY_SPECIFIED;

            }

            else
            {
                //User failed to specify a public key file after passing "-pub" as an argument
                print_error("No public key file specified after -pub argument");
                return 0xFFFFFFFF;
            }

            //prevent the loop from examining the next command line argument.
            //We don't need to because that's the name of the public keyfile
            i++;


        }

        //Secret Key file is specified with "-sec" and the next argument will be the name of the secret key file
        else if(strncmp("-sec", argv[i], 4) == 0)
        {
            if(NULL != argv[i + 1])
            {
                strncpy(Secret_Keyfile, argv[i + 1], 100);
                mask |= SECKEY_SPECIFIED;

            }

            else
            {
                //User failed to specify a secret key file after passing "-sec" as an argument
                print_error("No secret key file specified after -sec argument");
                return 0xFFFFFFFF;
            }

            //prevent the loop from examining the next command line argument.
            //We don't need to because that's the name of the secret keyfile
            i++;


        }


    }

    //We cannot simultaniously be in ENCRYPT, DECRYPT or KEYGEN mode. They are mutually exclusive.
    //Here we use a boolean algebra trick check to make sure this didn't happen
    temp = mask & 0x07;
    if(temp != ENCRYPT_MODE && temp != DECRYPT_MODE && temp != KEYGEN_MODE)
    {
        //we have violated the mutual exclusivity of ENCRYPT, DECRYPT, and KEYGEN mode
        //return an error
        print_error("Invalid arguments: Encrypt, Decrypt, and Keygen modes are mutually exclusive, and at least one must be specified");
        return 0xFFFFFFFF;
    }

    //Check to make sure the user specified public and secret keyfiles
    if( (PUBKEY_SPECIFIED & mask) == 0 || (SECKEY_SPECIFIED & mask) == 0 )
    {
        //The user failed to specify key files
        //If we are in keygen mode, this is okay, otherwise return an error
        if((KEYGEN_MODE & mask) != KEYGEN_MODE)
        {
            //We're not in keygen mode, and the user never specified keyfiles
            //Return an error
            print_error("Missing Keyfiles");
            return 0xFFFFFFFF;
        }

    }


    return mask;
}

unsigned long long get_stdin(unsigned char* input, FILE* infile)
{
    int temp;
    unsigned long long length = 0;


    //We need to get input from stdin, byte for byte, even if the input is random data
    //There has to be a cleaner way to do this, but this works for now
    while(1)
    {
        temp = fgetc(infile);
        input[length] = (char) temp;
        if(length >= MAX_STDIN_INPUT - 1) break;
        if(temp == EOF) break;
        length++;
    }

    return length;

}




//This function generates user keyfiles. It returns -1 on failure
int keyFileGen(char* PK_filename, char* SK_filename)
{
    //Curve25519 encryption keypair
    unsigned char myKey_public[crypto_box_PUBLICKEYBYTES];
    unsigned char myKey_secret[crypto_box_SECRETKEYBYTES];

    //Ed25519 signature keypair
    unsigned char myID_public[crypto_sign_PUBLICKEYBYTES];
    unsigned char myID_secret[crypto_sign_SECRETKEYBYTES];


    unsigned long long mlen = crypto_box_PUBLICKEYBYTES + crypto_sign_PUBLICKEYBYTES;

    unsigned char sig[crypto_sign_BYTES];

    //the total public key, including the encryption public key, signature public key, and the signature
    unsigned char totalKey_pk[crypto_box_PUBLICKEYBYTES + crypto_sign_PUBLICKEYBYTES + crypto_sign_BYTES];

    //the total secret key, including the encryption secret key, and the signature secret key
    unsigned char totalKey_sk[crypto_box_SECRETKEYBYTES + crypto_sign_SECRETKEYBYTES];

    //temporary buffer
    unsigned char temp[crypto_box_PUBLICKEYBYTES + crypto_sign_PUBLICKEYBYTES];

    FILE* public_fp;    //file for public key
    FILE* secret_fp;    //file for secret key

    sodium_memzero(totalKey_pk, sizeof(totalKey_pk));   //clear the public key buffer
    sodium_memzero(totalKey_sk, sizeof(totalKey_sk));   //clear the secret key buffer
    sodium_memzero(temp, sizeof(temp));                 //clear the temp buffer

    crypto_box_keypair(myKey_public, myKey_secret); //generate the encryption keypair
    crypto_sign_keypair(myID_public, myID_secret);  //generate the signature keypair

    //dump(myKey_public, "\nMyKey_public", crypto_box_PUBLICKEYBYTES);
    //dump(myID_public, "\nMyID_public", crypto_sign_PUBLICKEYBYTES);
    //dump(myKey_secret, "\nMyKey_secret", crypto_box_SECRETKEYBYTES);
    //dump(myID_secret, "\nMyID_secret", crypto_sign_SECRETKEYBYTES);

    //put the public encryption key, followed by the public signature key, into the temp buffer
    memcpy(temp, myKey_public, crypto_box_PUBLICKEYBYTES);
    memcpy(temp + crypto_box_PUBLICKEYBYTES, myID_public, crypto_sign_PUBLICKEYBYTES);


    //put the secret encryption key, followed by the secret signature key, into the totalKey_sk buffer
    memcpy(totalKey_sk, myKey_secret, crypto_box_SECRETKEYBYTES);
    memcpy(totalKey_sk + crypto_box_SECRETKEYBYTES, myID_secret, crypto_sign_SECRETKEYBYTES);

    //sign the public key with the secret signature key
    //every time the totalKey_pk is read, the signature will be verified
    crypto_sign_detached(sig, NULL, temp, mlen, myID_secret);

    //prepend the signature to the total public key
    memcpy(totalKey_pk, sig, crypto_sign_BYTES);
    memcpy(totalKey_pk + crypto_sign_BYTES, temp, mlen);

    sodium_memzero(myID_secret, sizeof(myID_secret));
    sodium_memzero(myKey_secret, sizeof(myKey_secret));


    //open the public and secret key files
    public_fp = fopen(PK_filename, "wb");
    if( NULL == public_fp )
    {
        return -1;
    }

    secret_fp = fopen(SK_filename, "wb");
    if( NULL == secret_fp )
    {
        return -1;
    }

    //write the public and secret keys to their files
    fwrite(totalKey_pk, sizeof(unsigned char), sizeof(totalKey_pk), public_fp);
    fwrite(totalKey_sk, sizeof(unsigned char), crypto_box_SECRETKEYBYTES + crypto_sign_SECRETKEYBYTES, secret_fp);

    fclose(public_fp);  //close the public key file
    fclose(secret_fp);  //close the secret key file

    sodium_memzero(totalKey_pk, sizeof(totalKey_pk));   //clear the public key buffer
    sodium_memzero(totalKey_sk, sizeof(totalKey_sk));   //clear the secret key buffer

    return 0;

}





//This function loads the Diffie-Hellman and Ed25519 public keys from the keyfile, and verifies the self-signature
int loadPublicKeyFromFile(char* KeyFile, unsigned char* PublicCryptKey, unsigned char* PublicSignKey)
{
    FILE* fp;

    size_t ok;

    unsigned char buffer[crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES + crypto_sign_PUBLICKEYBYTES];
    unsigned char signature[crypto_sign_BYTES];

    fp = fopen(KeyFile, "rb");
    if(NULL == fp)
    {
        //We could not open the file. Return error code 3
        return 3;
    }

    ok = fread(buffer, sizeof(char), crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES + crypto_sign_PUBLICKEYBYTES, fp);

    //Check to make sure all the bytes were read
    if( ok != (crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES + crypto_sign_PUBLICKEYBYTES) )
    {
        //We could not read the file properly. Return error code 3.
        return 3;
    }

    fclose(fp);

    //The first crypto_sign_BYTES of the public keyfile are the self-signature.
    //Copy it into the variable called 'signature'
    memcpy(signature, buffer, crypto_sign_BYTES);

    //The Diffie-Hellman public encryption key is crypto_box_PUBLICKEYBYTES long
    //and it begins crypto_sign_BYTES after the beginning of the file.
    //Copy it into the variable called 'PublicCryptKey'
    memcpy(PublicCryptKey, buffer + crypto_sign_BYTES, crypto_box_PUBLICKEYBYTES);

    //The Ed25519 public signature key is crypto_sign_PUBLICKEYBYTES long
    //and it begins crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES after the beginning of the file.
    //Copy it into the variable called 'PublicSignKey'
    memcpy(PublicSignKey, buffer + crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES, crypto_sign_PUBLICKEYBYTES);


    //dump(PublicCryptKey, "\nPublicCryptKey", crypto_sign_PUBLICKEYBYTES);
    //dump(PublicSignKey, "\nPublicSignKey", crypto_sign_PUBLICKEYBYTES);

    //Verify the self-signature on the keyfile
    return crypto_sign_verify_detached(signature, buffer + crypto_sign_BYTES, crypto_box_PUBLICKEYBYTES + crypto_sign_PUBLICKEYBYTES, PublicSignKey);

}




//This function loads the Diffie-Hellman and Ed25519 secret keys from the keyfile.
int loadSecretKeyFromFile(char* KeyFile, unsigned char* SecretCryptKey, unsigned char* SecretSignKey)
{
    FILE* fp;

    size_t ok;
    unsigned char buffer[crypto_box_SECRETKEYBYTES + crypto_sign_SECRETKEYBYTES];

    fp = fopen(KeyFile, "rb");
    if(NULL == fp)
    {
        //We could not open the file. Return error code 3
        return 3;
    }

    ok = fread(buffer, sizeof(char), crypto_box_SECRETKEYBYTES + crypto_sign_SECRETKEYBYTES, fp);

    //Check to make sure all the bytes were read
    if( ok != (crypto_box_SECRETKEYBYTES + crypto_sign_SECRETKEYBYTES) )
    {
        //We could not read the file properly. Return error code 3.
        return 3;
    }

    fclose(fp);

    //The Diffie-Hellman secret encryption key is the first crypto_box_SECRETKEYBYTES of the keyfile
    //Copy it into the variable called 'SecretCryptKey'
    memcpy(SecretCryptKey, buffer, crypto_box_PUBLICKEYBYTES);

    //The Ed25519 secret signature key is crypto_sign_SECRETKEYBYTES long
    //and it begins crypto_box_SECRETKEYBYTES after the beginning of the file.
    //Copy it into the variable called 'SecretSignKey'
    memcpy(SecretSignKey, buffer + crypto_box_SECRETKEYBYTES, crypto_sign_SECRETKEYBYTES);

    //dump(SecretCryptKey, "\nSecretCryptKey", crypto_box_SECRETKEYBYTES);
    //dump(SecretSignKey, "\nSecretSignKey", crypto_sign_SECRETKEYBYTES);

    //Success
    return 0;


}






//This function locks a plaintext message. It first derives the symmetric key
//by performing a signed Diffie-Hellman key exchange, and then encrypts
//and authenticates the plaintext with chacha20-poly1305
int lock_message(unsigned char* ciphertext,
            unsigned long long * ciphertext_len,
            unsigned char* plaintext,
            unsigned long long plaintext_len,
            unsigned char* Bob_publicKey,
            unsigned char* Alice_signKey)
{
    //ephemeral Diffie-Hellman keypair to be generated on-the-fly
    unsigned char ephemeral_publicKey[crypto_box_PUBLICKEYBYTES];
    unsigned char ephemeral_secretKey[crypto_box_SECRETKEYBYTES];

    //ephemeral Diffie-Hellman public key that is signed by Alice's signature key
    unsigned char ephemeral_publicKey_signed[crypto_box_PUBLICKEYBYTES + crypto_sign_BYTES];

    //The detached signature of Alice's ephemeral Diffie-Hellman keypair
    unsigned char signature[crypto_sign_BYTES];

    //length of the signature on Alice's ephemeral Diffie-Hellman keypair
    unsigned long long siglen;

    //shared secret key calculated from Diffie-Hellman Key Exchange
    unsigned char sharedKey[crypto_aead_chacha20poly1305_IETF_KEYBYTES];

    //nonce for the ChaCha20 encryption algorithm. Nonce is not cryptographically important in this scheme, so zero it.
    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES] = {0,0,0,0,0,0,0,0,0,0,0,0};


    int error_check;



    //Generate Alice's ephemeral Diffie-Hellman keypair
    crypto_box_keypair(ephemeral_publicKey, ephemeral_secretKey);

    //Sign Alice's ephemeral Diffie-Hellman public key so that the recipient can verify that the locked message is from Alice
    //This function will sign 'ephemeral_publicKey' with 'Alice_signKey', and place the signature in 'signature'
    //We can safely ignore 'siglen' and assume the signature will always be crypto_sign_BYTES long because
    //crypto_sign_detached() will zero-pad shorter signatures if necessary
    crypto_sign_detached(signature, &siglen, ephemeral_publicKey, crypto_box_PUBLICKEYBYTES, Alice_signKey);

    //Use pointer arithmetic to prepend the signature to Alice's ephemeral Diffie-Hellman public key.
    memcpy(ephemeral_publicKey_signed, signature, crypto_sign_BYTES);
    memcpy((ephemeral_publicKey_signed + crypto_sign_BYTES), ephemeral_publicKey, crypto_box_PUBLICKEYBYTES);



    //This function performs a Diffie-Hellman Key Exchange over Curve25519
    //and computes the shared secret key to be used by Alice and Bob
    error_check = crypto_box_beforenm(sharedKey, Bob_publicKey, ephemeral_secretKey);
    if(0 != error_check)
    {
        //Diffie-Hellman Key Exchange somehow failed
        //Not valid curve points perhaps?
        return -1;
    }

    //Now that we're done with the ephemeral key, we need to erase the secret
    //half from memory to prevent side-channel leaks
    sodium_memzero(ephemeral_secretKey, sizeof(ephemeral_secretKey));


    //This function uses the ChaCha20 stream cipher to encrypt the plaintext.
    //It also uses poly1305 to authenticate the ciphertext and Alice's signed ephemeral Diffie-Hellman public key
    crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext + sizeof(ephemeral_publicKey_signed),
                                        ciphertext_len,
                                        plaintext,
                                        plaintext_len,
                                        ephemeral_publicKey_signed,
                                        sizeof(ephemeral_publicKey_signed),
                                        NULL,
                                        nonce,
                                        sharedKey);

    //Now we prepend Alice's signed Diffie-Hellman public key to the authenticated and encrypted message
    memcpy(ciphertext, ephemeral_publicKey_signed, sizeof(ephemeral_publicKey_signed));


    //Erase the shared secret key from memory now that we've successfully used it to encrypt the message.
    sodium_memzero(sharedKey, sizeof(sharedKey));

    *ciphertext_len += sizeof(ephemeral_publicKey_signed);

    return 0;
}






//This function verifies and decrypts a message that was locked with 'lock_message()'
//First, it verifies the signed ephemeral Diffie-Hellman public key to verify the sender's
//identity. Then it verifies the poly1305 MAC and decrypts the chacha20 encrypted ciphertext.
//This function returns 0 on success, and returns -1 if cryptographic verification fails.
int unlock_message(unsigned char* plaintext,
                unsigned long long* plaintext_len,
                unsigned char* ciphertext,
                unsigned long long ciphertext_len,
                unsigned char* Alice_publicSignKey,
                unsigned char* Bob_secretKey)
{
    //ephemeral Diffie-Hellman keypair to be generated on-the-fly
    unsigned char ephemeral_publicKey[crypto_box_PUBLICKEYBYTES];

    //Bob's Diffie-Hellman public key. This will be calculated from his secret key
    unsigned char Bob_publicKey[crypto_box_PUBLICKEYBYTES];

    //ephemeral Diffie-Hellman public key that is signed by Alice's signature key
    unsigned char ephemeral_publicKey_signed[crypto_box_PUBLICKEYBYTES + crypto_sign_BYTES];

    //The detached signature of Alice's ephemeral Diffie-Hellman keypair
    unsigned char signature[crypto_sign_BYTES];

    //shared secret key calculated from Diffie-Hellman Key Exchange
    unsigned char sharedKey[crypto_aead_chacha20poly1305_IETF_KEYBYTES];

    //nonce for the ChaCha20 encryption algorithm. Nonce is not cryptographically important in this scheme, so zero it.
    unsigned char nonce[crypto_aead_chacha20poly1305_IETF_NPUBBYTES] = {0,0,0,0,0,0,0,0,0,0,0,0};

    int error_check;

    //Compute Bob's public key given his secret key that we passed in
    crypto_scalarmult_base(Bob_publicKey, Bob_secretKey);

    //Use clever pointer arithmetic to get Alice's signed ephemeral
    //public key out of the beginning of the ciphertext
    memcpy(ephemeral_publicKey_signed, ciphertext, sizeof(ephemeral_publicKey_signed));
    memcpy(ephemeral_publicKey, ephemeral_publicKey_signed + crypto_sign_BYTES, crypto_box_PUBLICKEYBYTES);
    memcpy(signature, ephemeral_publicKey_signed, crypto_sign_BYTES);

    //Now, we verify the signature on Alice's ephemeral Diffie-Hellman public key
    error_check = crypto_sign_verify_detached(signature, ephemeral_publicKey, sizeof(ephemeral_publicKey), Alice_publicSignKey);
    if(0 != error_check)
    {
        print_error("Signature Verification Failed");
        return -1;
    }

    //This function performs a Diffie-Hellman Key Exchange over Curve25519
    //and computes the shared secret key to be used by Alice and Bob
    error_check = crypto_box_beforenm(sharedKey, ephemeral_publicKey, Bob_secretKey);
    if(0 != error_check)
    {
        //Diffie-Hellman Key Exchange somehow failed
        //Not valid curve points perhaps?
        return -1;
    }


    //This function verifies the poly1305 MAC computed over Alice's signed ephemeral Diffie-Hellman public key
    //and the ciphertext, then it decrypts the ChaCha20 encrypted message. It returns -1 if verification fails
    error_check = crypto_aead_chacha20poly1305_ietf_decrypt(plaintext,
                                                    plaintext_len,
                                                    NULL,
                                                    ciphertext + sizeof(ephemeral_publicKey_signed),
                                                    ciphertext_len - sizeof(ephemeral_publicKey_signed),
                                                    ephemeral_publicKey_signed,
                                                    sizeof(ephemeral_publicKey_signed),
                                                    nonce,
                                                    sharedKey);

    if(0 != error_check)
    {
        print_error("MAC Verification Failed");
    }


    //Erase the shared secret key from memory now that we've successfully used it to decrypt the message.
    sodium_memzero(sharedKey, sizeof(sharedKey));

    return error_check;
}
