all:
	gcc -O0 -lcrypto -o decrypt decrypt_ssl.c
	gcc -O0 -lcrypto -o encrypt encrypt_ssl.c
decrypt:
	gcc -O0 -lcrypto -o decrypt decrypt_ssl.c
encrypt:
	gcc -O0 -lcrypto -o encrypt encrypt_ssl.c
clear:
	rm -rf encrypt decrypt
