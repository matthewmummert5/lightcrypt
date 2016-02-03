#ifndef LOCK_MESSAGE_H
#define LOCK_MESSAGE_H

/*	The purpose of this function is to lock a message. First, it signes the plaintext with the sender's identity key using NaCl's crypto_sign(), then it authenticates and encrypts the signed message with NaCl's crypto_box() function
*	Then, it arranges the message to the following format:
*
*							nonce||sender's ephemeral public key || MAC || ciphertext(signed plaintext message)
*
*	This function returns -1 on error
*/

int lock_message(unsigned char* c, const unsigned char* m, unsigned long long mlen, unsigned long long *lmlen, const unsigned char* recipient_pk, const unsigned char* sender_sk, const unsigned char* sender_pk, const unsigned char *senderID_sk);


/*	The purpose of this function is to unlock a message. First, it reads the nonce, and the sender's ephemeral public key from the first part of the file
*	Then, it verifies the MAC and decrypts the ciphertext using NaCl's crypto_box_open(). After that, it verify's the sender's signature on the plaintext using NaCl's crypto_sign_open().
*
*	This function returns -1 if decryption or signature verification fails.
*/
int unlock_message(unsigned char* m, unsigned char* c, unsigned long long lmlen, unsigned long long *mlen, const unsigned char* senderID_pk, const unsigned char* recipient_sk);

#endif
