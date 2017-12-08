#include <string.h>
#include <openssl/evp.h>

#define MAX_KEY_LEN 64

unsigned char key[MAX_KEY_LEN] = {""};
char *default_skey = "2016-05-25-entry";
const int LEN = 1024;

int main(int argc, char** argv)
{
    //check args
    if(argc < 2) {
        printf("Usage:\n    %s password [skey]  ## length(skey)<64, default skey=%s\n", 
            argv[0], default_skey);
        exit(1);
    } else if(argc < 3) {
        memcpy(key, default_skey, strlen(default_skey));
    } else {
        if(strlen(argv[2]) >= 64) {
            printf("error:length(skey) >=64!\n");
            exit(1);
        }
        memcpy(key, argv[2], strlen(argv[2]));
    }

    EVP_CIPHER_CTX ctx; 
    const EVP_CIPHER* cipher = EVP_rc4();
    int len = 0;
    int i;
    
    //Base64
    EVP_ENCODE_CTX ectx;
    EVP_DecodeInit(&ectx);

    unsigned char out[LEN];
    bzero(out, LEN);
	
    int outl = 0;

    EVP_DecodeUpdate(&ectx, out, &outl, argv[1], strlen(argv[1]));
    len = outl;
    EVP_DecodeFinal(&ectx, out+len, &outl);
    len += outl;
    //DES
    EVP_CIPHER_CTX_init(&ctx);
    if (EVP_DecryptInit_ex(&ctx, cipher, NULL, key, NULL) != 1) {
        printf("EVP_DecryptInit_ex() failed\n");
        return -1;
    }
	char inter[LEN];
	bzero(inter, LEN);
	int interl = 0;
	int lene = 0;
	if (EVP_DecryptUpdate(&ctx, inter, &interl, (unsigned char*)out, len) != 1) {
        printf("EVP_DecryptUpdate() failed\n");
        return -2;
    }
	lene = interl;
	if (EVP_DecryptFinal_ex(&ctx, inter+len, &interl) != 1) {
        printf("EVP_DecryptFinal_ex() failed\n");
        return -3;
    }
    lene += interl;
    EVP_CIPHER_CTX_cleanup(&ctx);
    //if last LF,then change it. 
    if (out[len-1] == 10) out[len-1] = '\0';
    printf("%s", inter);
    if (i < argc - 1) printf(" ");

    printf("\n");
    return 0;
}
