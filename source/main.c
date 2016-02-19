#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <randombytes.h>
#include <lock.h>
#include <inits.h>
#include <tweetnacl.h>

#define MAX_INPUT 24576

//A function for getting what the user passed in from stdin
unsigned long long get_stdin(unsigned char* input, FILE* infile);

//a function for generating keyfiles
int keyFileGen(void);

//verifies that a public key is valid
int keyVerify(unsigned char* signed_pubKey, unsigned long long length);

//a function for debugging purposes
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


int main(int argc, char *argv[])
{
	struct crypt_keypair ephemeral;		//ephemeral keypair that Alice generates to encrypt a message to Bob
	struct crypt_keypair AliceKey;		//The sender (Alice) long term public encryption key
	struct crypt_keypair BobPubKey;		//The recipient's (Bob) long term public encryption key, to be read from a file
	struct sign_keypair AliceIdentity;	//Alice's identity key, to be read from a file
	struct sign_keypair BobIdentity;	//Bob's identity key, to be read from a file

	FILE* AliceKeyFile;					//file containing Alice's keys
	FILE* BobKeyFile;					//file containing Bob's keys
	FILE* OutputFile;					//optional output file

	unsigned char plaintext[MAX_INPUT];	//the plaintext message to be encrypted
	unsigned long long mlength;			//the length of the plaintest message
	unsigned long long lmlen;			//The length of the locked message
	int error;							//an error variable
	int mode;							//the mode that this program is operating in: encrypt, decrypt: or keygen
	int filesize;						//variable for keeping track of the size of the key files
	
	//the ciphertext will be placed in here
	unsigned char ciphertext[MAX_INPUT + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + crypto_box_ZEROBYTES];
	unsigned char buffer[512];
	
	memset(plaintext, 0x00, MAX_INPUT);
	memset(ciphertext, 0x00, MAX_INPUT + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + crypto_box_ZEROBYTES);
	

	//Check to see if user passed in any command line arguments
	if(1 == argc)
	{
		printf("ERROR: No command line arguments passed in\n");
		return 1;
	}

	//encrypt mode
	if(0 == strcmp("-e", argv[1]))
	{
		mode = 1;
	}

	//decrypt mode
	else if(0 == strcmp("-d", argv[1]))
	{
		mode = 2;
	}

	//keygen mode
	else if(0 == strcmp("-keygen", argv[1]))
	{
		mode = 3;
	}

	else
	{
		printf("error\n");
		return 1;
	}

	//here we execute the proper operation, encrypt, decrypt, or keygen, depending on the mode	
	switch(mode)
	{
		case 1: //encrypt


			//get the input from stdin			
			mlength = get_stdin(plaintext, stdin);
			
			//open user's private identity key
			AliceKeyFile = fopen(argv[2], "rb");
			if(NULL == AliceKeyFile)
			{
				printf("Cannot open file: %s\n", argv[2]);
				return 1;
			}

			//open Bob's public key
			BobKeyFile = fopen(argv[3], "rb");
			if(NULL == BobKeyFile)
			{
				printf("Cannot open file: %s\n", argv[3]);
				return 1;
			}
			
			//read the keys from the files
			fread(buffer, sizeof(unsigned char), crypto_box_SECRETKEYBYTES + crypto_sign_SECRETKEYBYTES, AliceKeyFile);
			memcpy(AliceIdentity.sk, buffer + crypto_box_SECRETKEYBYTES , crypto_sign_SECRETKEYBYTES);			


			memset(buffer, 0x00, sizeof(buffer));	//clear the buffer
	
			fseek(BobKeyFile, 0, SEEK_END);	//Seek to the end of the file
			filesize = ftell(BobKeyFile); 	//Check the position of the file, which equals the size of the file in bytes
			fseek(BobKeyFile, 0, SEEK_SET);	//Seek back to the beginning of the file
			
			//read the entire contents of the public key file		
			fread(buffer, sizeof(unsigned char), filesize, BobKeyFile);
			
			//Check the signature on the public key file
			if( 0!= keyVerify(buffer, filesize))
			{
				printf("The public key specified is invalid\n");
				return 1;
			}

			//put Bob's public key from the public key file into BobPubKey.sk
			memcpy(BobPubKey.pk, buffer + (filesize - crypto_box_PUBLICKEYBYTES - crypto_sign_PUBLICKEYBYTES),crypto_box_PUBLICKEYBYTES);

			memset(buffer, 0x00, sizeof(buffer));	//clear the buffer

			
			crypto_box_keypair(ephemeral.pk, ephemeral.sk);	//generate Alice's ephemeral keypair
	
			//Sign, encrypt, and authenticate the plaintext message
			error = lock_message(ciphertext, plaintext, mlength, &lmlen, BobPubKey.pk, ephemeral.sk, ephemeral.pk, AliceIdentity.sk);
			if(-1 == error)
			{
				//encryption somehow failed, return an error code
				printf("Error Encrypting\n");
				return 1;
			}

			//Check to see if user specified an output file
			if(NULL == argv[4])
			{
				//The user did not specify an output file
				//route output to stdout instead
				fwrite(ciphertext, sizeof(unsigned char), lmlen, stdout);
			}

			else
			{
				OutputFile = fopen(argv[4], "wb");
				if(NULL == OutputFile)
				{
					//could not properly open the output file
					//print an error and return error code 1
					printf("Could not open output file\n");
					return 1;
				}
				//wite the ciphertext to the ouput file
				fwrite(ciphertext, sizeof(unsigned char), lmlen, OutputFile);


				fclose(OutputFile);

			}

			
			//close the keyfiles
			fclose(AliceKeyFile);
			fclose(BobKeyFile);

			break;




		case 2: //decrypt


			//get the input from stdin			
			lmlen = get_stdin(ciphertext, stdin);
			
			//check to make sure that there was input from stdin			
			if(0 == lmlen)
			{
				return 1;
			}
			
			//open the sender's Identity file
			BobKeyFile = fopen(argv[3], "rb");
			if(NULL == BobKeyFile)
			{
				printf("Cannot open file: %s\n", argv[3]);
				return 1;
			}

			//open the recipient's Secret Key
			AliceKeyFile = fopen(argv[2], "rb");
			if(NULL == AliceKeyFile)
			{
				printf("Cannot open file: %s\n", argv[2]);
				return 1;
			}

			fseek(BobKeyFile, 0, SEEK_END);	//Seek to the end of the file
			filesize = ftell(BobKeyFile); 	//Check the position of the file, which equals the size of the file in bytes
			fseek(BobKeyFile, 0, SEEK_SET);	//Seek back to the beginning of the file
	
			fread(buffer, sizeof(unsigned char), filesize, BobKeyFile);
			
			//Check the signature on the public key file
			if( 0!= keyVerify(buffer, filesize))
			{
				printf("The public key specified is invalid\n");
				return 1;
			}
			
			memcpy(BobIdentity.pk, buffer + (filesize - crypto_sign_PUBLICKEYBYTES), crypto_sign_PUBLICKEYBYTES);

			memset(buffer, 0x00, sizeof(buffer));

			
			fread(buffer, sizeof(unsigned char), crypto_sign_SECRETKEYBYTES + crypto_box_SECRETKEYBYTES, AliceKeyFile);
			memcpy(AliceKey.sk, buffer, crypto_box_SECRETKEYBYTES);	

			memset(buffer, 0x00, sizeof(buffer));		



			
			//verify and decrypt the locked message
			error = unlock_message(plaintext, ciphertext, lmlen, &mlength, BobIdentity.pk, AliceKey.sk);
			if(-1 == error)
			{
				printf("Data verification/decryption failed!!!\nTHE MESSAGE MAY HAVE BEEN TAMPERED WITH BY AN ATTACKER\n");
				//decryption and/or verification somehow failed, return an error code
				//This could be a man in the middle attack
				return 1;
			}

			//Check to see if user specified an output file
			if(NULL == argv[4])
			{
				//The user did not specify an output file
				//route output to stdout instead
				fwrite(plaintext, sizeof(unsigned char), mlength, stdout);
			}

			else
			{
				OutputFile = fopen(argv[4], "wb");
				if(NULL == OutputFile)
				{
					//could not properly open the output file
					//print an error and return error code 1
					printf("Could not open output file\n");
					return 1;
				}
				//wite the plaintext to the ouput file
				fwrite(plaintext, sizeof(unsigned char), mlength, OutputFile);


				fclose(OutputFile);

			}

			fclose(AliceKeyFile);
			fclose(BobKeyFile);
			
			break;


		case 3: //keygen

			error = keyFileGen();
			if(0 != error)
			{
				printf("Error creating keyfiles\nExiting Program!\n");
				return 1;
			}
			
			
		
			break;

		default:
			printf("ERROR\n");
			return 1;
			break;



	}		
	//return 0 for success*/
	return 0;
}


int keyFileGen(void)
{
	struct crypt_keypair myKey;	//Curve25519 encryption keypair
	struct sign_keypair myID;	//Ed25519 signature keypair

	unsigned long long smlen;
	unsigned long long mlen = crypto_box_PUBLICKEYBYTES + crypto_sign_PUBLICKEYBYTES;
	
	//the total public key, including the encryption public key, signature public key, and the signature
	unsigned char totalKey_pk[crypto_box_PUBLICKEYBYTES + crypto_sign_PUBLICKEYBYTES + crypto_sign_BYTES];

	//the total secret key, including the encryption secret key, and the signature secret key
	unsigned char totalKey_sk[crypto_box_SECRETKEYBYTES + crypto_sign_SECRETKEYBYTES];

	//temporary buffer
	unsigned char temp[crypto_box_PUBLICKEYBYTES + crypto_sign_PUBLICKEYBYTES];

	FILE* public_fp;	//file for public key
	FILE* secret_fp;	//file for secret key
	
	memset(totalKey_pk, 0x00, sizeof(totalKey_pk)); //clear the public key buffer
	memset(totalKey_sk, 0x00, sizeof(totalKey_sk));	//clear the secret key buffer
	memset(temp, 0x00, sizeof(temp));				//clear the temp buffer
	
	crypto_box_keypair(myKey.pk, myKey.sk);	//generate the encryption keypair
	crypto_sign_keypair(myID.pk, myID.sk);	//generate the signature keypair

	//put the public encryption key, followed by the public signature key, into the temp buffer
	memcpy(temp, myKey.pk, crypto_box_PUBLICKEYBYTES);
	memcpy(temp + crypto_box_PUBLICKEYBYTES, myID.pk, crypto_sign_PUBLICKEYBYTES);

	
	//put the secret encryption key, followed by the secret signature key, into the totalKey_sk buffer
	memcpy(totalKey_sk, myKey.sk, crypto_box_SECRETKEYBYTES);
	memcpy(totalKey_sk + crypto_box_SECRETKEYBYTES, myID.sk, crypto_sign_SECRETKEYBYTES);

	//sign the public key with the secret signature key
	//every time the totalKey_pk is read, the signature will be verified
	crypto_sign(totalKey_pk, &smlen, temp, mlen, myID.sk);


	//open the public and secret key files
	public_fp = fopen("MyKey.pub", "wb");
	if( NULL == public_fp )
	{
		return -1;
	}

	secret_fp = fopen("MyKey.sec", "wb");
	if( NULL == secret_fp )
	{
		return -1;
	}

	//write the public and secret keys to their files
	fwrite(totalKey_pk, sizeof(unsigned char), smlen, public_fp);
	fwrite(totalKey_sk, sizeof(unsigned char), crypto_box_SECRETKEYBYTES + crypto_sign_SECRETKEYBYTES, secret_fp);
	
	fclose(public_fp);	//close the public key file
	fclose(secret_fp);	//close the secret key file

	memset(totalKey_pk, 0x00, sizeof(totalKey_pk)); //clear the public key buffer
	memset(totalKey_sk, 0x00, sizeof(totalKey_sk));	//clear the secret key buffer
	
	return 0;

}

int keyVerify(unsigned char* signed_pubKey, unsigned long long length)
{
	unsigned long long mlen;
	unsigned char pubKey[crypto_box_PUBLICKEYBYTES + crypto_sign_PUBLICKEYBYTES + crypto_sign_BYTES];
	unsigned char pk[crypto_sign_PUBLICKEYBYTES];

	//get the signing key out of the total public key
	memcpy(pk, signed_pubKey + (length - crypto_sign_PUBLICKEYBYTES), crypto_sign_PUBLICKEYBYTES);

	//verify the total public key with the signing key
	return crypto_sign_open(pubKey, &mlen, signed_pubKey, length, pk);
	
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
		if(length >= MAX_INPUT - 1) break;
		if(temp == EOF) break;
		length++;
	}

	return length;

}






