#include<stdio.h>
#include<stdlib.h>
#include<pbc.h>
#include "pbc_inshort.h"
//int Number_of_attribute = 10;
#define  Number_of_attribute 10

struct PublicKey {
	element_t g;
	element_t g1;
	element_t g2;
	element_t g3;
	element_t w[Number_of_attribute];
};

struct MasterSecertKey {
	element_t a;
	element_t b;
	element_t g2_a;
};

struct UserPrivateKey {
	element_t sk1[Number_of_attribute];
	element_t sk2[Number_of_attribute];
	element_t sk3;
};

struct CipherText {
	element_t C0;
	element_t C1;
	element_t C2;
	element_t C_star_1[Number_of_attribute];
	element_t C_star_2[Number_of_attribute];
	element_t sigma;
};


struct TransformationKey {
	element_t T;
	element_t sk1[Number_of_attribute];
	element_t sk2[Number_of_attribute];
	element_t sk3;
	element_t sk4;
};


struct TranformedCiphertext{
	element_t C0;
	element_t C2;
	element_t Tmp1;
	element_t Tmp2;
	element_t Tmp3;

};

void Setup(struct PublicKey * PK, struct MasterSecertKey * msk, pairing_t pairing);

void Extract (struct UserPrivateKey * sk, struct PublicKey * PK, struct MasterSecertKey * msk,pairing_t pairing);

void Encryption (struct CipherText * CT,struct PublicKey *PK, pairing_t pairing);

void TransformationKeyGeneration (struct TransformationKey * TK, struct UserPrivateKey * sk, struct PublicKey *PK ,pairing_t pairing);

void PartialDecrypt(struct TranformedCiphertext *CTp, struct CipherText * CT, struct TransformationKey * TK, struct PublicKey * PK, pairing_t pairing);

void Decrypt(struct TransformationKey * TK, struct TranformedCiphertext * CTp, struct PublicKey * PK , pairing_t pairing);
