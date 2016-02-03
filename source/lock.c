#include <lock.h>
#include <tweetnacl.h>
#include <randombytes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*	The purpose of this function is to lock a message. First, it signes the plaintext with the sender's identity key using NaCl's crypto_sign(), then it authenticates and encrypts the signed message with NaCl's crypto_box() function
*	Then, it arranges the message to the following format:
*
*							nonce||sender's ephemeral public key || MAC || ciphertext(signed plaintext message)
*
*	This function returns -1 on error
*/

int lock_message(unsigned char* c, const unsigned char* m, unsigned long long mlen, unsigned long long *lmlen, const unsigned char* recipient_pk, const unsigned char* sender_sk, const unsigned char* sender_pk, const unsigned char *senderID_sk)
{
	//Calculate the length of the cipher text
	//The ciphertext is the encrypted plaintext, plus the sender's public key, the sender's signature, and the nonce
	unsigned long long clen = mlen + crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + crypto_box_ZEROBYTES + crypto_box_BOXZEROBYTES;
	unsigned long long smlen; //the length of the signed message

	
	unsigned char nonce[crypto_box_NONCEBYTES]; //Nonce used in crypto_box()
	unsigned char *buffer;
	unsigned char *sm; //the signed message
	int error;
	
	*lmlen = mlen + crypto_sign_BYTES + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES + crypto_box_BOXZEROBYTES;

	//Allocate some memory for the signes message
	//return an error if allocation failed
	sm = malloc(mlen + crypto_sign_BYTES);
	if(NULL == sm)
	{
		return -1;
	}

	buffer = malloc((size_t) clen);
	if(NULL == buffer)
	{
		return -1;
	}



	//First, we sign the plaintext message with the sender's private key.
	error = crypto_sign(sm,&smlen,m,mlen,senderID_sk);
	
	//Get a random nonce. If /dev/urandom is properly seeded, the risk of nonce collision is negligible.
	randombytes(nonce, crypto_box_NONCEBYTES);	

	
	//copy the signed message to the buffer to be encrypted
	memcpy( (buffer + crypto_box_ZEROBYTES), sm, smlen);

	//encrypt and authenticate the signed plaintext
	error = crypto_box(c, buffer, smlen + crypto_box_ZEROBYTES, nonce, recipient_pk, sender_sk);
	
	//Do the memory juggling act
	//I really wish NaCl wouldn't force you to do this
	memcpy(buffer, nonce, crypto_box_NONCEBYTES);
	memcpy(buffer + crypto_box_NONCEBYTES, sender_pk, crypto_box_PUBLICKEYBYTES);
	memcpy(buffer + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES, c + crypto_box_BOXZEROBYTES, clen - crypto_box_BOXZEROBYTES - crypto_box_PUBLICKEYBYTES - crypto_box_NONCEBYTES);
	memcpy(c, buffer, clen);
	
	//zero the memory that we're not using anymore
	//memset(nonce, 0x00, crypto_box_NONCEBYTES);
	memset(buffer, 0x00, clen);
	memset(sm, 0x00, smlen);

	
	free(buffer);
	free(sm);
	
	return error;
}


/*	The purpose of this function is to unlock a message. First, it reads the nonce, and the sender's ephemeral public key from the first part of the file
*	Then, it verifies the MAC and decrypts the ciphertext using NaCl's crypto_box_open(). After that, it verify's the sender's signature on the plaintext using NaCl's crypto_sign_open().
*
*	This function returns -1 if decryption or signature verification fails.
*/

int unlock_message(unsigned char* m, unsigned char* c, unsigned long long lmlen, unsigned long long *mlen, const unsigned char* senderID_pk, const unsigned char* recipient_sk)
{
	unsigned char sender_pk[crypto_box_PUBLICKEYBYTES]; //the sender's public key
	unsigned char nonce[crypto_box_NONCEBYTES]; //the message nonce
	unsigned char* sm; //the signed message
	unsigned char* buffer;

	unsigned long long smlen = lmlen - crypto_box_NONCEBYTES - crypto_box_PUBLICKEYBYTES - crypto_box_BOXZEROBYTES;
	int error;
	
	//reserve some memory for the signed message
	sm = malloc(lmlen);
	if(NULL == sm)
	{
		return -1;
	}
	
	//reserve some memory for the buffer
	buffer = malloc(lmlen - crypto_box_PUBLICKEYBYTES - crypto_box_NONCEBYTES + crypto_box_BOXZEROBYTES);
	if(NULL == sm)
	{
		return -1;
	}
	
	memset(buffer, 0x00, lmlen - crypto_box_PUBLICKEYBYTES - crypto_box_NONCEBYTES + crypto_box_BOXZEROBYTES);

	//First, we need to extract the nonce and sender's ephemeral public key from the message
	
	//get the nonce from the message
	memcpy(nonce, c, crypto_box_NONCEBYTES);

	//get the sender's ephemeral public key from the message
	memcpy(sender_pk, c + crypto_box_NONCEBYTES, crypto_box_PUBLICKEYBYTES);

	//copy the encrypted message to the buffer
	memcpy(buffer + crypto_box_BOXZEROBYTES, c + crypto_box_NONCEBYTES + crypto_box_PUBLICKEYBYTES,  lmlen - crypto_box_NONCEBYTES - crypto_box_PUBLICKEYBYTES );
	
	//verify the MAC and decrypt the ciphertext
	error = crypto_box_open(sm, buffer, lmlen - crypto_box_NONCEBYTES - crypto_box_PUBLICKEYBYTES + crypto_box_BOXZEROBYTES, nonce, sender_pk, recipient_sk);
	if(-1 == error)
	{
		//This means that verifying the MAC failed
		//return the error signal
		printf("MAC Verification Error!\n");
		return -1;
	}
	
	//now that we have the decrypted message, we need to verify the sender's signature
	error = crypto_sign_open(m, mlen, sm + crypto_box_ZEROBYTES, smlen, senderID_pk);
	if(-1 == error)
	{
		//This means that signature verification failed
		//return an error
		printf("Signature Verification Error!\n");
		return -1;
	}
	
	//zero and free the memory that we used
	memset(buffer, 0x00, lmlen - crypto_box_PUBLICKEYBYTES - crypto_box_NONCEBYTES + crypto_box_BOXZEROBYTES);
	memset(sm, 0x00, lmlen - crypto_box_PUBLICKEYBYTES - crypto_box_NONCEBYTES);
	
	free(buffer);
	free(sm);


	//if we've reached this point, then the message has been verified successfully
	return 0;


}




















