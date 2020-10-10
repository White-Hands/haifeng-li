#include"pbc_inshort.h"

void init_pairing(pairing_t pairing){
	char filedir[] = "param/a.param";
	printf("param :%s\n",filedir);
	FILE * fp = fopen(filedir,"r");
	char param[2048];
	size_t count = fread(param,1,2048,fp);
	if (!count) pbc_die("input error");
	fclose(fp);
	pairing_init_set_str(pairing,param);
}


void Zr(element_t n,pairing_t pairing){
	element_init_Zr(n,pairing);
	element_random(n);
}

void G1(element_t n,pairing_t pairing){
	element_init_G1(n,pairing);
	element_random(n);
}
void G2(element_t n,pairing_t pairing){
	element_init_G2(n,pairing);
	element_random(n);
}

void GT(element_t n,pairing_t pairing){
	element_init_GT(n,pairing);
	element_random(n);
}
