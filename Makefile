enc: rsa_demo.c
	gcc -orsa_demo rsa_demo.c -lcrypto -lssl -g
genkey:
	openssl genrsa -out private_key.pem 2048
	openssl rsa -in private_key.pem -pubout -out public_key.pem
clean: 
	rm -rf rsa_demo.o rsa_demo
