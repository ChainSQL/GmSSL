#pragma once
#ifndef GMALG_H_INCLUDE
#define GMALG_H_INCLUDE
#include <vector>

typedef void* HANDLE;

//SM2 interface
//Generate Publick&Secret Key
__attribute__ ((visibility ("default"))) int sm2GenKeyPair(
    std::vector<unsigned char> &publicKey,
    std::vector<unsigned char> &privateKey);
//SM2 Sign&Verify
__attribute__ ((visibility ("default"))) unsigned long sm2Sign(
    std::pair<unsigned char *, int> &pri4Sign,
    unsigned char *pInData,
    unsigned long ulInDataLen,
    std::vector<unsigned char> &signedDataV);
__attribute__ ((visibility ("default"))) unsigned long sm2Verify(
    unsigned char* pub4Verify,
    int pub4VerifyLen,
    unsigned char *pInData,
    unsigned long ulInDataLen,
    unsigned char *pSignValue,
    unsigned long ulSignValueLen);
//SM2 Encrypt&Decrypt
__attribute__ ((visibility ("default"))) unsigned long sm2Encrypt(
    unsigned char* pub4Encrypt,
    int pub4EncryptLen,
    unsigned char *pPlainData,
    unsigned long ulPlainDataLen,
    std::vector<unsigned char> &cipherDataV);
__attribute__ ((visibility ("default"))) unsigned long sm2Decrypt(
    std::pair<unsigned char *, int> &pri4Decrypt,
    unsigned char *pCipherData,
    unsigned long ulCipherDataLen,
    std::vector<unsigned char> &plainDataV);

//SM3 interface
__attribute__ ((visibility ("default"))) unsigned long sm3HashTotal(
    unsigned char *pInData,
    unsigned long ulInDataLen,
    unsigned char *pHashData,
    unsigned long *pulHashDataLen);
// unsigned long SM3HashInit(EVP_MD_CTX *phSM3Handle);
__attribute__ ((visibility ("default"))) unsigned long sm3HashInit(HANDLE *phSM3Handle);
__attribute__ ((visibility ("default"))) unsigned long sm3HashFinal(void *phSM3Handle, unsigned char *pHashData, unsigned long *pulHashDataLen);
__attribute__ ((visibility ("default"))) void sm3HashUpdate(void *phSM3Handle, void const *data, std::size_t size) noexcept;

//SM4 Symetry Encrypt&Decrypt
__attribute__ ((visibility ("default"))) unsigned long sm4SymEncrypt(
    unsigned int uiAlgMode,
    unsigned char *pSessionKey,
    unsigned long pSessionKeyLen,
    unsigned char *pPlainData,
    unsigned long ulPlainDataLen,
    unsigned char *pCipherData,
    unsigned long *pulCipherDataLen);
__attribute__ ((visibility ("default"))) unsigned long sm4SymDecrypt(
    unsigned int uiAlgMode,
    unsigned char *pSessionKey,
    unsigned long pSessionKeyLen,
    unsigned char *pCipherData,
    unsigned long ulCipherDataLen,
    unsigned char *pPlainData,
    unsigned long *pulPlainDataLen);

#endif