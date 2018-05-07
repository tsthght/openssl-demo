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
 * 生成共要和私钥
 * tsthght@yeah.net
 */

void keygen(int size) {
	RSA *key = NULL;
	FILE *fp = NULL;
	BIO *buf = NULL;
	int len = 0;

	char str_buf[51200];
	if((key = RSA_generate_key(size, 3, NULL, NULL)) == NULL) {
		printf("%s\n", ERR_error_string(ERR_get_error(), NULL));
		exit(EXIT_FAILURE);
	}
	if(RSA_check_key(key) < 1) {
		printf("Error: Problems while generating RSA Key.\n");
		exit(EXIT_FAILURE);
	}
	fp = fopen(PRIKEY, "w");
	buf = BIO_new(BIO_s_mem());
	if((PEM_write_bio_RSAPrivateKey(buf, key, NULL, NULL, 0, NULL, NULL)) == 0) {
	//if(PEM_write_RSAPrivateKey(fp, key, NULL, NULL, 0, 0, NULL) == 0) {
		printf("Error: Problems while writing RSA Private Key.\n");
		BIO_free(buf);
		exit(EXIT_FAILURE);
	}
	len = BIO_pending(buf);
	memset(str_buf, 0, 51200);
	BIO_read(buf, (void *)str_buf, len);
	fwrite(str_buf, strlen(str_buf), 1, fp);
	BIO_free(buf);
	fclose(fp);
	fp = fopen(PUBKEY, "w");
	buf = BIO_new(BIO_s_mem());
	if((PEM_write_bio_RSA_PUBKEY(buf, key)) == 0) {
	//if(PEM_write_RSAPublicKey(fp, key) == 0) {
		printf("Error: Problems while writing RSA Public Key.\n");
		BIO_free(buf);
		exit(EXIT_FAILURE);
	}
	len = BIO_pending(buf);
	memset(str_buf, 0, 51200);
	BIO_read(buf, (void *)str_buf, len);
	fwrite(str_buf, strlen(str_buf), 1, fp);
	fclose(fp);
	BIO_free(buf);
	return ;
}

int main(int argc, char **argv) {
	int key = argc>1? atoi(argv[1]):1024;
	keygen(key);
	return 0;
}

