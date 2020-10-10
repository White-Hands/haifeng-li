#include "haifeng-li.h"
//int Number_of_attribute = 10;

void Setup(struct PublicKey * PK, struct MasterSecertKey * msk, pairing_t pairing){
	/*init msk*/
	G1(PK->g2,pairing);
	G1(msk->g2_a,pairing);
	Zr(msk->a,pairing);
	Zr(msk->b,pairing);

	/* g2^a */
	element_pow_zn(msk->g2_a,PK->g2,msk->a);

	/*init PK*/	
	G1(PK->g,pairing);
	G1(PK->g1,pairing);
	element_pow_zn(PK->g1,PK->g,msk->a);

	G1(PK->g3,pairing);
	element_t temp1_setup;	// 用来存放a-1*b的值
	Zr(temp1_setup,pairing);
	element_invert(temp1_setup,msk->a);
	element_mul(temp1_setup,temp1_setup,msk->b);
	element_pow_zn(PK->g3,PK->g2,temp1_setup);

	/* wi */
	for(int i=0;i<Number_of_attribute;i++){
		Zr(PK->w[i],pairing);
	}

	puts("Setup");

}

void Extract (struct UserPrivateKey * sk, struct PublicKey * PK, struct MasterSecertKey * msk, pairing_t pairing){

	element_t U[Number_of_attribute];
	element_t d;
	Zr(d,pairing);

	element_t temp_extract1,temp_extract2,temp_extract3,hi;
	Zr(temp_extract1,pairing);
	G1(temp_extract2,pairing);
	G1(temp_extract3,pairing);
	G1(hi,pairing);

	element_add(temp_extract1,msk->a,d);		// temp_extract1 = a+d
	element_pow_zn(temp_extract3,PK->g2,temp_extract1);		// temp_3 = g2^a+d


	for(int i=0;i<Number_of_attribute;i++){
		Zr(U[i],pairing);
		G1(sk->sk1[i],pairing);
		G1(sk->sk2[i],pairing);

		element_from_hash(hi,PK->w[i],sizeof(element_t));
		element_pow_zn(temp_extract2,PK->g1,PK->w[i]);
		element_mul(temp_extract2,temp_extract2,hi);
		element_pow_zn(temp_extract2,temp_extract2,U[i]);

		/* sk1 */
		element_mul(sk->sk1[i],temp_extract3,temp_extract2);

		/* sk2 */
		element_pow_zn(sk->sk2[i],PK->g,U[i]);
	}
 
 	/* sk3 */
	G1(sk->sk3,pairing);
	element_invert(temp_extract1,msk->b);
	element_mul(temp_extract1,temp_extract1,d);		//b-1*d
	element_pow_zn(sk->sk3,PK->g1,temp_extract1);

	puts("Extract");

}

void Encryption (struct CipherText * CT,struct PublicKey *PK, pairing_t pairing) {
	/*init qi and secret value r about attribute encryption*/
	element_t qi[Number_of_attribute];

	for(int i=0;i<Number_of_attribute;i++){
		Zr(qi[i],pairing);
	}
	element_t r;
	Zr(r,pairing);
	element_set0(r);
	/* r = Sum(qi) */
	for(int i=0;i<Number_of_attribute;i++){
		element_add(r,r,qi[i]);
	}

	//GT(CT->C,pairing);
	element_t M;
	Zr(M,pairing);	// M is a random member in Zr
	element_set1(M);

	/* K */
 	Zr(CT->C0,pairing);
 	element_t temp_encryption;
 	GT(temp_encryption,pairing);
 	element_pairing(temp_encryption,PK->g1,PK->g2);
 	element_pow_zn(temp_encryption,temp_encryption,r);
 	element_from_hash(CT->C0,temp_encryption,sizeof(temp_encryption));

 	/* C0 */
 	element_add(CT->C0,CT->C0,M);

 	/* h */
 	element_t h;
 	Zr(h,pairing); 	// hash is replaceable, there is replaced by h(M)
 	element_from_hash(h,M,sizeof(M));		//h = H(M)

 	/* C1 */
 	G1(CT->C1,pairing);
 	element_pow_zn(CT->C1,PK->g3,r);

 	/* C2 */
 	G1(CT->C2,pairing);
 	element_pow_zn(CT->C2,PK->g,h);

 	element_t hi;
 	G1(hi,pairing);
 	
 	/*Cstar1 and cstar2*/
 	for(int i=0; i<Number_of_attribute;i++){
 	/*CT->C_star_1*/
 		G1(CT->C_star_1[i],pairing);
 		element_pow_zn(CT->C_star_1[i],PK->g,qi[i]);
 	/*CT->C_star_2*/
 		G1(CT->C_star_2[i],pairing);
 		element_pow_zn(CT->C_star_2[i],PK->g1,PK->w[i]);
 		element_from_hash(hi,PK->w[i],sizeof(element_t));
 		element_mul(CT->C_star_2[i],CT->C_star_2[i],hi);
 		element_pow_zn(CT->C_star_2[i],CT->C_star_2[i],qi[i]);
  	}

  	/* sigma */
  	G1(CT->sigma,pairing);
  	element_from_hash(CT->sigma,CT->C2,sizeof(element_t));	// sigma = hash(c2)^h
  	element_pow_zn(CT->sigma,CT->sigma,h);

 	puts("Encryption");
}


void TransformationKeyGeneration (struct TransformationKey * TK, struct UserPrivateKey * sk, struct PublicKey *PK ,pairing_t pairing) {
	Zr(TK->T,pairing);

	/*init sk1 and sk2 */
	for(int i=0;i<Number_of_attribute;i++){
		G1(TK->sk1[i],pairing);
		G1(TK->sk2[i],pairing);
		element_pow_zn(TK->sk1[i],sk->sk1[i],TK->T);
		element_pow_zn(TK->sk2[i],sk->sk2[i],TK->T);
	}

	/* sk3 */
	G1(TK->sk3,pairing);
	element_pow_zn(TK->sk3,sk->sk3,TK->T);

	/* sk4 */
	G1(TK->sk4,pairing);
	element_pow_zn(TK->sk4,PK->g,TK->T);
	puts("GenTKout");
}



void PartialDecrypt(struct TranformedCiphertext *CTp, struct CipherText * CT, struct TransformationKey * TK, struct PublicKey * PK, pairing_t pairing){
	/* C0 and C2*/
	Zr(CTp->C0,pairing);
	G1(CTp->C2,pairing);	
	element_set(CTp->C0,CT->C0);
	element_set(CTp->C2,CT->C2);
	
	/* Tmp1*/
	GT(CTp->Tmp1,pairing);
	element_set1(CTp->Tmp1);

	element_t temp_up;
	element_t temp_down;
	element_t temp_Tmp[Number_of_attribute];
	GT(temp_up,pairing);
	GT(temp_down,pairing);
	for(int i=0;i<Number_of_attribute;i++){
		element_pairing(temp_up,CT->C_star_1[i],TK->sk1[i]);
		element_pairing(temp_down,CT->C_star_2[i],TK->sk2[i]);
		GT(temp_Tmp[i],pairing);
		element_div(temp_Tmp[i],temp_up,temp_down);

	}
	for(int i=0;i<Number_of_attribute;i++){
		element_mul(CTp->Tmp1,CTp->Tmp1,temp_Tmp[i]);
	}

	element_pairing(temp_down,TK->sk3,CT->C1);

	element_div(CTp->Tmp1,CTp->Tmp1,temp_down);

	/* Tmp2 */
	GT(CTp->Tmp2,pairing);
	element_pairing(CTp->Tmp2,CT->sigma,TK->sk4);

	/* Tmp3 */
	element_t temp_decrypt;
	G1(temp_decrypt,pairing);
	GT(CTp->Tmp3,pairing);
	element_from_hash(temp_decrypt,CT->C2,sizeof(CT->C2));
	element_pairing(CTp->Tmp3,temp_decrypt,CT->C2);

	puts("PartialDecrypt");
}

void Decrypt(struct TransformationKey * TK, struct TranformedCiphertext * CTp, struct PublicKey * PK, pairing_t pairing){
	/*Temp*/
	element_t Temp;
	GT(Temp,pairing);

	element_t T_invert;

	Zr(T_invert,pairing);
	element_invert(T_invert,TK->T);
	element_pow_zn(Temp,CTp->Tmp1,T_invert);

	/* K */
	element_t K;
	Zr(K,pairing);
	element_from_hash(K,Temp,sizeof(Temp));

	/* M */
	element_t M;
	Zr(M,pairing);
	element_sub(M,CTp->C0,K);

	/* h */
	element_t h;
	element_from_hash(h,M,sizeof(M));

	/* C2 =? g^h */
	element_t temp_end1,temp_end2;
	G1(temp_end1,pairing);
	element_pow_zn(temp_end1,PK->g,h);

	/* Tmp2 =? Tmp3^t */
	GT(temp_end2,pairing);
	element_pow_zn(temp_end2,CTp->Tmp3,TK->T);

	puts("Decrypt");

	if(element_cmp(CTp->C2,temp_end1) && element_cmp(CTp->Tmp2,temp_end2))
		puts("Failed!");
	else
		puts("Succeed");

}
