#ifndef __ENCRYPT_H__
#define __ENCRYPT_H__

#include "Export.h"
#include "..\\openssl\\include\\ossl_typ.h"
#include <string>
#include <vector>

class UTILITY_API CEncrypter
{
public:
    static std::string MD5String(const std::string& plain);
    static std::string MD5File(const std::string& file);
    static std::string Base64Encode(const unsigned char* pData, int len);
    static long Base64Decode(const std::string& cipher, unsigned char* pout, long buflen);
    static std::string RSAPublicEncrypt(const std::string& plain, const std::string& publicKey);
    static std::string RSAPrivateDecrypt(const std::string& cipher, const std::string& privateKey);
    static std::string RSAPrivateEncrypt(const std::string& plain, const std::string& privateKey);
    static std::string RSAPublicDecrypt(const std::string& cipher, const std::string& publicKey);
    static long AesEncrypt(const std::string& plain, const std::string& strKey, std::string& cipher);
    static long AesDecrypt(const std::string& cipher, const std::string& strKey, std::string& plain);

private:
    static unsigned char* aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len);
    static unsigned char* aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len);
};



#endif  // __ENCRYPT_H__