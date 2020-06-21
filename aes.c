#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

static const unsigned char S_Box[16][16] = {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab,
                                            0x76,
                                            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72,
                                            0xc0,
                                            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31,
                                            0x15,
                                            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2,
                                            0x75,
                                            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f,
                                            0x84,
                                            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58,
                                            0xcf,
                                            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f,
                                            0xa8,
                                            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3,
                                            0xd2,
                                            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
                                            0x73,
                                            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b,
                                            0xdb,
                                            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4,
                                            0x79,
                                            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae,
                                            0x08,
                                            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b,
                                            0x8a,
                                            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d,
                                            0x9e,
                                            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28,
                                            0xdf,
                                            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb,
                                            0x16};

static const unsigned char S_Box_I[16][16] = {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7,
                                              0xfb,
                                              0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9,
                                              0xcb,
                                              0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3,
                                              0x4e,
                                              0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1,
                                              0x25,
                                              0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6,
                                              0x92,
                                              0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d,
                                              0x84,
                                              0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45,
                                              0x06,
                                              0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a,
                                              0x6b,
                                              0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
                                              0x73,
                                              0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf,
                                              0x6e,
                                              0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe,
                                              0x1b,
                                              0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a,
                                              0xf4,
                                              0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec,
                                              0x5f,
                                              0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c,
                                              0xef,
                                              0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99,
                                              0x61,
                                              0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c,
                                              0x7d};

static const unsigned char ConstColMat[4][4] = {2, 3, 1, 1,
                                                1, 2, 3, 1,
                                                1, 1, 2, 3,
                                                3, 1, 1, 2};

static const unsigned char InvConstColMat[4][4] = {0xe, 0xb, 0xd, 0x9,
                                                   0x9, 0xe, 0xb, 0xd,
                                                   0xd, 0x9, 0xe, 0xb,
                                                   0xb, 0xd, 0x9, 0xe};

static const unsigned int RCon[10] = {0x01000000, 0x02000000,
                                      0x04000000, 0x08000000,
                                      0x10000000, 0x20000000,
                                      0x40000000, 0x80000000,
                                      0x1b000000, 0x36000000};

static unsigned int exKey[44];
const static unsigned char *pExKey = (unsigned char *) exKey;

static void convertToMatrix(unsigned char *str, unsigned char matrix[4][4]) {
    //将16字节组转换成4x4的矩阵
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            matrix[j][i] = *(str + i * 4 + j);
        }
    }
}

static void convertToBytes(unsigned char matrix[4][4], unsigned char *dst) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            *(dst + i * 4 + j) = matrix[j][i];
        }
    }
}

static void printMatrix(unsigned char matrix[4][4]) {
    //矩阵打印
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%02X, ", matrix[i][j]);
        }
        printf("\n");
    }
}

static void subByte(unsigned char *pByte) {
    //单个字节代换
    int low4bits = *pByte & 0xf;
    int high4bits = (*pByte >> 4) & 0xf;
    *pByte = S_Box[high4bits][low4bits];
}

static void InvSubByte(unsigned char *pByte) {
    //单个字节逆代换
    int low4bits = *pByte & 0xf;
    int high4bits = (*pByte >> 4) & 0xf;
    *pByte = S_Box_I[high4bits][low4bits];
}

static void subBytes(unsigned char matrix[4][4]) {
    //字节代换
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            subByte(&matrix[i][j]);
}

static void InvSubBytes(unsigned char matrix[4][4]) {
    //逆字节代换
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            InvSubByte(&matrix[i][j]);
}


static void shiftRows(unsigned char matrix[4][4]) {
    //行位移
    unsigned char temp[4] = {0};
    for (int i = 1; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            temp[j] = matrix[i][(j + i) % 4];
        }
        for (int j = 0; j < 4; j++) {
            matrix[i][j] = temp[j];
        }
    }
}

static void InvShiftRows(unsigned char matrix[4][4]) {
    //逆行位移
    unsigned char temp[4] = {0};
    for (int i = 1; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            temp[j] = matrix[i][(j + 4 - i) % 4];
        }
        for (int j = 0; j < 4; j++) {
            matrix[i][j] = temp[j];
        }
    }
}

static unsigned char XTIME(unsigned char x) {
    return ((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

static unsigned char GFMul(unsigned char a, unsigned char b) {
    //GF(2^8)有限域乘法
    unsigned char temp[8] = {a};
    unsigned char tempmul;

    for (int i = 1; i < 8; i++) {
        temp[i] = XTIME(temp[i - 1]);
    }
    tempmul = (b & 0x01) * a;
    for (int i = 1; i <= 7; i++) {
        tempmul ^= (((b >> i) & 0x01) * temp[i]);
    }
    return tempmul;
}

static void mixCols(unsigned char matrix[4][4]) {
    //列混合
    unsigned char tempMat[4][4];

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            tempMat[i][j] = matrix[i][j];
        }
    }
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            matrix[i][j] = GFMul(ConstColMat[i][0], tempMat[0][j]) ^ GFMul(ConstColMat[i][1], tempMat[1][j]) ^ GFMul(ConstColMat[i][2], tempMat[2][j]) ^
                           GFMul(ConstColMat[i][3], tempMat[3][j]);
        }
    }
}

static void InvMixCols(unsigned char matrix[4][4]) {
    //逆列混合
    unsigned char tempMat[4][4];

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            tempMat[i][j] = matrix[i][j];
        }
    }
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            matrix[i][j] =
                    GFMul(InvConstColMat[i][0], tempMat[0][j]) ^ GFMul(InvConstColMat[i][1], tempMat[1][j]) ^ GFMul(InvConstColMat[i][2], tempMat[2][j]) ^
                    GFMul(InvConstColMat[i][3], tempMat[3][j]);
        }
    }
}

static unsigned int T(unsigned int word, int round) {
    //密钥拓展的字变换函数
    //1.字左移一个字节
    word = (word << 8) ^ ((word & 0xff000000) >> 24);
    //2.字节代换
    unsigned char *pWord = (unsigned char *) &word;
    for (int i = 0; i < 4; i++) {
        subByte(&pWord[i]);
    }
    //3.轮常量异或
    return word ^ RCon[round];
}

static void keyExpansion(unsigned char *key) {
    //密钥拓展
    for (int i = 0; i < 4; i++) {
        exKey[i] = key[i * 4 + 3] ^ (key[i * 4 + 2] << 8) ^ (key[i * 4 + 1] << 16) ^ (key[i * 4 + 0] << 24);
    }
    for (int i = 1; i < 11; i++) {
        exKey[i * 4 + 0] = exKey[i * 4 - 4] ^ T(exKey[i * 4 - 1], i - 1);
        exKey[i * 4 + 1] = exKey[i * 4 - 3] ^ exKey[i * 4];
        exKey[i * 4 + 2] = exKey[i * 4 - 2] ^ exKey[i * 4 + 1];
        exKey[i * 4 + 3] = exKey[i * 4 - 1] ^ exKey[i * 4 + 2];
    }
}

static void addRoundKey(unsigned char matrix[4][4], int round) {
    //轮密钥加
    for (int i = 0; i < 4; i++) {
        matrix[0][i] ^= pExKey[round * 16 + i * 4 + 3];
        matrix[1][i] ^= pExKey[round * 16 + i * 4 + 2];
        matrix[2][i] ^= pExKey[round * 16 + i * 4 + 1];
        matrix[3][i] ^= pExKey[round * 16 + i * 4];
    }
}

static int zeroPadding(const char *raw, unsigned char **dst) {
    int len = strlen(raw);
    len = (len % 16) ? ((len / 16 + 1) * 16) : (len + 16);
    *dst = (unsigned char *) malloc(sizeof(unsigned char) * len);
    memset(*dst, 0, len);
    strcpy((char *) *dst, raw);
    return len;
}

static void hexdump(unsigned char *p, int len) {
    for (int i = 0; i < len / 16; i++) {
        for (int j = 0; j < 16; j++) {
            printf("%02X ", *(p + 16 * i + j));
        }
        printf("\n");
    }
    printf("\n");
}

unsigned char *aes(char *raw_plaintext, char *raw_key) {
    unsigned char *plaintext = NULL, *ciphertext = NULL, *key = NULL;
    unsigned char matrix[4][4] = {0};
    int plen = zeroPadding(raw_plaintext, &plaintext);

    ciphertext = (unsigned char *) malloc(sizeof(char) * plen + 1);
    memset(ciphertext, 0, plen + 1);

    zeroPadding(raw_key, &key);
    keyExpansion(key);

    printf("[*] THE HEX OF PADDING PLAINTEXT:\n");
    hexdump(plaintext, plen);

    for (int i = 0; i < plen / 16; i++) {
        convertToMatrix(plaintext + i * 16, matrix);
        addRoundKey(matrix, 0);
        for (int j = 1; j < 10; j++) {
            subBytes(matrix);
            shiftRows(matrix);
            mixCols(matrix);
            addRoundKey(matrix, j);
        }
        subBytes(matrix);
        shiftRows(matrix);
        addRoundKey(matrix, 10);
        convertToBytes(matrix, ciphertext + i * 16);
    }

    printf("[*] THE HEX OF CIPHERTEXT:\n");
    hexdump(ciphertext, plen);
    return ciphertext;
}

static void hexStr2Bytes(char *src, unsigned char *dst, int len) {
    //16进制字符串转字节流
    unsigned char high4bits, low4bits;

    len *= 2;
    for (int i = 0; i < len; i += 2) {
        high4bits = toupper(src[i]);
        low4bits = toupper(src[i + 1]);
        (high4bits > 0x39) ? (high4bits -= 0x37) : (high4bits -= 0x30);
        (low4bits > 0x39) ? (low4bits -= 0x37) : (low4bits -= 0x30);
        dst[i / 2] = (high4bits << 4) | low4bits;
    }
}

unsigned char *bytes2hexStr(unsigned char *src, int len) {
    //字节流转16进制字符串
    int i;
    unsigned char szTmp[3], *dst = NULL;
    dst = (unsigned char *) malloc(sizeof(unsigned char) * (len * 2 + 1));
    memset(dst, 0, len * 2 + 1);
    memset(szTmp, 0, 3);
    for (i = 0; i < len; i++) {
        sprintf(szTmp, "%02x", (unsigned char) src[i]);
        memcpy(&dst[i * 2], szTmp, 2);
    }
    return dst;
}

unsigned char *deAes(char *raw_ciphertext, char *raw_key) {
    unsigned char *plaintext = NULL, *ciphertext = NULL, *key = NULL;
    unsigned char matrix[4][4] = {0};

    int clen = strlen(raw_ciphertext) / 2;    //两位16进制为一个字节
    if (clen % 16) {
        printf("[-] Ciphertext length should be a multiple of 16(Bytes)!\n");
        return NULL;
    }

    ciphertext = (unsigned char *) malloc(sizeof(unsigned char) * (clen + 1));
    plaintext = (unsigned char *) malloc(sizeof(unsigned char) * (clen + 1));
    memset(ciphertext, 0, clen + 1);
    memset(plaintext, 0, clen + 1);
    hexStr2Bytes(raw_ciphertext, ciphertext, clen);

    zeroPadding(raw_key, &key);
    keyExpansion(key);

    printf("[*] THE HEX OF CIPHERTEXT:\n");
    hexdump(ciphertext, clen);

    for (int i = 0; i < clen / 16; i++) {
        convertToMatrix(ciphertext + i * 16, matrix);
        addRoundKey(matrix, 10);
        for (int j = 9; j >= 1; j--) {
            InvShiftRows(matrix);
            InvSubBytes(matrix);
            addRoundKey(matrix, j);
            InvMixCols(matrix);
        }
        InvShiftRows(matrix);
        InvSubBytes(matrix);
        addRoundKey(matrix, 0);
        convertToBytes(matrix, plaintext + i * 16);
    }
    printf("[*] THE HEX OF PLAINTEXT:\n");
    hexdump(plaintext, clen);

    return plaintext;
};