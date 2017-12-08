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

    int i;
    //1. DES
    EVP_CIPHER_CTX_init(&ctx);
    if (EVP_EncryptInit_ex(&ctx, cipher, NULL, key, NULL) != 1) {
        printf("EVP_EncryptInit_ex() failed\n");
        return -1;
    }

    unsigned char* in = argv[1];
    int inl = strlen(in);

    unsigned char inter[LEN];
    bzero(inter, LEN);
    int interl = 0;

    if (EVP_EncryptUpdate(&ctx, inter, &interl, in, inl) != 1) {
        printf("EVP_EncryptUpdate() failed\n");
        return -2;
    }
    int len = interl;
    if (EVP_EncryptFinal_ex(&ctx, inter+len, &interl) != 1) {
        printf("EVP_EncryptFinal_ex() failed\n");
        return -3;
    }
    len += interl;
    EVP_CIPHER_CTX_cleanup(&ctx);

    //2. Base64
    EVP_ENCODE_CTX ectx;
    EVP_EncodeInit(&ectx);

    unsigned char out[LEN];
    bzero(out, LEN);
    int outl = 0;

    EVP_EncodeUpdate(&ectx, out, &outl, inter, len);
    len = outl;
    EVP_EncodeFinal(&ectx, out+len, &outl);
    len += outl;

    if (out[len-1] == 10) out[len-1] = '\0';
    printf("%s", out);
    if (i < argc - 1) printf(" ");

    printf("\n");
	return 0;
}
