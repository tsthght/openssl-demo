#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define PRIKEY "private_key.pem"
#define PUBKEY "public_key.pem"
#define BUFFSIZE 4096

/*
 * RSA加密函数
 * author: tsthght@yeah.net
 */

char *my_encrypt(const char *str, const char *pubkey_path) {
	RSA *rsa = NULL;
	FILE *fp = NULL;
	char *en = NULL;
	int len = 0;
	int rsa_len = 0;

	//打开公钥文件
	if((fp = fopen(pubkey_path, "r")) == NULL) {
		return NULL;
	}
	//读取公钥PEM
	// You might try PEM_read_RSA_PUBKEY() instead of PEM_read_RSAPublicKey().
	// this is all about formats
	// PEM_read_RSA_PUBKEY() reads the PEM format. 
	// PEM_read_RSAPublicKey(0 reads the PKCS#1 format. 
	//if((rsa = PEM_read_RSAPublicKey(fp, 0, 0, 0)) == NULL) {
	if((rsa = PEM_read_RSA_PUBKEY(fp, 0, 0, 0)) == NULL) {
		fclose(fp);
		return NULL;
	}
	//打印公钥
	RSA_print_fp(stdout, rsa, 0);
	//获得待加密文件的文件长度
	len = strlen(str);
	//获得RSA钥模长度
	rsa_len = RSA_size(rsa);
	//加密后数据缓存
	en = (char *)malloc(rsa_len + 1);
	memset(en, 0, rsa_len + 1);
	//公钥加密数据
	if(RSA_public_encrypt(len, (unsigned char *)str, (unsigned char *)en, rsa, RSA_PKCS1_PADDING) < 0) {
		RSA_free(rsa);
		fclose(fp);
		return NULL;
	}
	RSA_free(rsa);
	fclose(fp);
	return en;
}	

char *my_decrypt(const char *str, const char *prikey_path ) {
	RSA *rsa = NULL;
	FILE *fp = NULL;
	char *de = NULL;
	int rsa_len = 0;

	//打开私钥文件
	if((fp = fopen(prikey_path, "r")) == NULL) {
		return NULL;
	}	
	//读取私钥PEM
	if((rsa = PEM_read_RSAPrivateKey(fp, 0, 0, 0)) == NULL) {
		fclose(fp);
		return NULL;
	}
	//打印私钥
	RSA_print_fp(stdout, rsa, 0);
	//获得RSA钥模长度
	rsa_len = RSA_size(rsa);
	//解密后数据缓存
	de = (char *)malloc(rsa_len + 1);
	memset(de, 0, rsa_len + 1);
	//私钥解密数据
	if(RSA_private_decrypt(rsa_len, (unsigned char *)str, (unsigned char *)de, rsa, RSA_PKCS1_PADDING) < 0) {
		RSA_free(rsa);
		fclose(fp);
		return NULL;
	}	
	RSA_free(rsa);
	fclose(fp);
	return de;
}

int main(int argc, char **argv) {
	char *src = argc<2?"hello, world":argv[1];	
	char *en = NULL;
	char *de = NULL;

	char *pubkey = argc<3?strdup(PUBKEY):argv[2];
	char *prikey = argc<4?strdup(PUBKEY):argv[3];

	printf("src is: %s\n", src);

	en = my_encrypt(src, PUBKEY);
	printf("enc is: %s\n", en == NULL? "error!":en);

	de = my_decrypt(en, PRIKEY);
	printf("dec is: %s\n", de == NULL? "error!":de);

	if(en != NULL) {
		free(en);
	}
	if(de != NULL) {
		free(de);
	}	
	return 0;
}
