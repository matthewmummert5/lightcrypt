#include <tweetnacl.h>

struct crypt_keypair
{
	unsigned char pk[crypto_box_PUBLICKEYBYTES];//public key
	unsigned char sk[crypto_box_SECRETKEYBYTES];//secret key
};

struct sign_keypair
{
	unsigned char pk[crypto_sign_PUBLICKEYBYTES];
	unsigned char sk[crypto_sign_SECRETKEYBYTES];
	
};


