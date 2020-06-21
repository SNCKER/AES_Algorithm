#include <stdio.h>
#include "aes.h"

int main() {
    unsigned char *ciphertext = NULL, *hexStrOfCiphertext = NULL;
    ciphertext = aes("1234567890abcdef", "sncker");
    hexStrOfCiphertext = bytes2hexStr(ciphertext, 32);    //"D6D4FC6F2735E04D0A9AF017BD57AC6C28B610717D7FDA1F2BA9602645FAF6D8"
    //printf("%s", deAes("D6D4FC6F2735E04D0A9AF017BD57AC6C28B610717D7FDA1F2BA9602645FAF6D8", "sncker"));
    printf("%s", deAes(hexStrOfCiphertext, "sncker"));
    return 0;
}
