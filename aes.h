//
// Created by SNCKER on 2020/6/2.
//

#ifndef AES_ALGORITHM_AES_H
#define AES_ALGORITHM_AES_H

/*
 * 功能：AES加密函数
 * 参数说明：
 * raw_plaintext : 明文字符串
 * raw_key : 密钥
 * 返回值：
 * 密文地址
 * */
unsigned char *aes(char *raw_plaintext, char *raw_key);

/*
 * 功能：AES解密函数
 * 参数说明：
 * raw_ciphertext : 密文字节字符串
 * raw_key : 密钥字符串
 * 返回值：
 * 明文地址
 *
 * */
unsigned char *deAes(char *raw_ciphertext, char *raw_key);

/*
 * 功能：字节流转16进制字符串
 * 参数说明：
 * src : 字节流首地址
 * len : 转换长度
 * 返回值：
 * 转换后的字符串地址
 *
 * */
unsigned char *bytes2hexStr(unsigned char *src, int len);

#endif //AES_ALGORITHM_AES_H