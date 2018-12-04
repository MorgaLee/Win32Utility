#include "stdafx.h"
#include "Encrypt.h"

#include "..\\openssl\\include\\md5.h"
#include "..\\openssl\\include\\rsa.h"
#include "..\\openssl\\include\\bio.h"
#include "..\\openssl\\include\\pem.h"
#include "..\\openssl\\include\\evp.h"
#include "..\\openssl\\include\\aes.h"
#include "..\\openssl\\include\\err.h"

#pragma comment(lib, "..\\openssl\\lib\\libeay32.lib")
#pragma comment(lib, "..\\openssl\\lib\\ssleay32.lib")

static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

static inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string CEncrypter::MD5String(const std::string& plain)
{
    if (plain.empty())
    {
        return std::string();
    }

    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, plain.c_str(), plain.size());
    unsigned char md[16];
    memset(md, 0, 16);
    MD5_Final(md, &ctx);
    return std::string((char*)md);
}

std::string CEncrypter::MD5File(const std::string& file)
{
    if (file.empty())
    {
        return std::string();
    }

    FILE* pf = NULL;
    fopen_s(&pf, file.c_str(), "rb");
    if (pf == NULL)
    {
        return std::string();
    }

    fseek(pf, 0, SEEK_END);
    long len = ftell(pf);
    rewind(pf);
    unsigned char* pContent = new unsigned char[len];
    memset(pContent, 0, len);
    fread(pContent, sizeof(unsigned char), len, pf);
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, pContent, len);
    unsigned char md[16];
    memset(md, 0, 16);
    MD5_Final(md, &ctx);
    delete[] pContent;
    pContent = NULL;
    fclose(pf);
    pf = NULL;
    return std::string((char*)md);
}

std::string CEncrypter::Base64Encode(const unsigned char* pData, int len)
{
    if (pData == NULL || len <= 0)
    {
        return "";
    }

    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (len--) {
        char_array_3[i++] = *(pData++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i <4); i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i)
    {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];

        while ((i++ < 3))
            ret += '=';

    }

    return ret;
}

long CEncrypter::Base64Decode(const std::string& cipher, unsigned char* pout, long buflen)
{
    int in_len = cipher.size();
    if (buflen < in_len)
    {
        return -1;
    }

    int i = 0;
    int j = 0;
    int in_ = 0;
    long count = 0;
    unsigned char char_array_4[4], char_array_3[3];

    while (in_len-- && (cipher[in_] != '=') && is_base64(cipher[in_])) {
        char_array_4[i++] = cipher[in_]; in_++;
        if (i == 4) {
            for (i = 0; i <4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
            {
                pout[count++] += char_array_3[i];
            }

            i = 0;
        }
    }

    if (i) {
        for (j = 0; j < i; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);

        for (j = 0; (j < i - 1); j++)
        {
            pout[count++] += char_array_3[j];
        }
    }

    return count;
}

std::string CEncrypter::RSAPublicEncrypt(const std::string& plain, const std::string& publicKey)
{
    if (plain.empty() || publicKey.empty())
    {
        return "";
    }

    BIO* bio = BIO_new_mem_buf((void*)publicKey.c_str(), -1); // -1: assume string is null terminated
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // NO NL
    RSA* rsaPubKey = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    if (rsaPubKey == NULL)
    {
        printf("ERROR: Could not load PRIVATE KEY!  PEM_read_bio_RSAPrivateKey FAILED: %s\n", ERR_error_string(ERR_get_error(), NULL));
        BIO_free(bio);
        return "";
    }

    BIO_free(bio);
    char cipher[1024];
    memset(cipher, 0, 1024);
    int num = RSA_public_encrypt(plain.length(), (unsigned char*)plain.c_str(), (unsigned char*)cipher, rsaPubKey, RSA_PKCS1_PADDING);
    return Base64Encode((unsigned char*)cipher, num);
}

std::string CEncrypter::RSAPrivateDecrypt(const std::string& cipher, const std::string& privateKey)
{
    BIO *bio = BIO_new_mem_buf((void*)privateKey.c_str(), -1);
    //BIO_set_flags( bio, BIO_FLAGS_BASE64_NO_NL ) ; // NO NL
    RSA* rsaPrivKey = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);

    if (!rsaPrivKey)
    {
        printf("ERROR: Could not load PRIVATE KEY!  PEM_read_bio_RSAPrivateKey FAILED: %s\n", ERR_error_string(ERR_get_error(), NULL));
        BIO_free(bio);
        return "";
    }

    BIO_free(bio);
    char plain[1024];
    memset(plain, 0, 1024);
    RSA_private_decrypt(cipher.length(), (unsigned char*)cipher.c_str(), (unsigned char*)plain, rsaPrivKey, RSA_PKCS1_PADDING);
    return plain;
}

std::string CEncrypter::RSAPrivateEncrypt(const std::string& plain, const std::string& privateKey)
{
    BIO *bio = BIO_new_mem_buf((void*)privateKey.c_str(), -1);
    //BIO_set_flags( bio, BIO_FLAGS_BASE64_NO_NL ) ; // NO NL
    RSA* rsaPrivKey = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);

    if (!rsaPrivKey)
    {
        printf("ERROR: Could not load PRIVATE KEY!  PEM_read_bio_RSAPrivateKey FAILED: %s\n", ERR_error_string(ERR_get_error(), NULL));
        BIO_free(bio);
        return "";
    }

    BIO_free(bio);
    char cipher[1024];
    memset(cipher, 0, 1024);
    int num = RSA_private_encrypt(plain.length(), (unsigned char*)plain.c_str(), (unsigned char*)cipher, rsaPrivKey, RSA_PKCS1_PADDING);
    return Base64Encode((unsigned char*)cipher, num);
}

std::string CEncrypter::RSAPublicDecrypt(const std::string& cipher, const std::string& publicKey)
{
    BIO* bio = BIO_new_mem_buf((void*)publicKey.c_str(), -1); // -1: assume string is null terminated
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // NO NL
    RSA* rsaPubKey = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    if (rsaPubKey == NULL)
    {
        printf("ERROR: Could not load PRIVATE KEY!  PEM_read_bio_RSAPrivateKey FAILED: %s\n", ERR_error_string(ERR_get_error(), NULL));
        BIO_free(bio);
        return "";
    }

    BIO_free(bio);
    char plain[1024];
    memset(plain, 0, 1024);
    RSA_public_decrypt(cipher.length(), (unsigned char*)cipher.c_str(), (unsigned char*)plain, rsaPubKey, RSA_PKCS1_PADDING);
    return plain;
}

long CEncrypter::AesEncrypt(const std::string& plain, const std::string& strKey, std::string& cipher)
{
    if (plain.empty() || strKey.empty())
    {
        return -1;
    }

    unsigned char iv[32];
    memset(iv, 0, 32);
    unsigned char key[32];
    memset(key, 0, 32);
    int keybit = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), NULL, (unsigned char*)strKey.c_str(), strKey.size(), 5, key, iv);
    if (keybit != 32)
    {
        return -1;
    }

    EVP_CIPHER_CTX en_ctx;
    EVP_CIPHER_CTX_init(&en_ctx);
    EVP_EncryptInit_ex(&en_ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)strKey.c_str(), iv);
    int len = plain.size() + 1;
    unsigned char* pout = aes_encrypt(&en_ctx, (unsigned char*)plain.c_str(), &len);
    cipher = Base64Encode(pout, len);
    free(pout);
    EVP_CIPHER_CTX_cleanup(&en_ctx);
    return len;
}

long CEncrypter::AesDecrypt(const std::string& cipher, const std::string& strKey, std::string& plain)
{
    if (cipher.empty() || strKey.empty())
    {
        return -1;
    }

    unsigned char iv[32];
    memset(iv, 0, 32);
    unsigned char key[32];
    memset(key, 0, 32);
    int keybit = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), NULL, (unsigned char*)strKey.c_str(), strKey.size(), 5, key, iv);
    if (keybit != 32)
    {
        return -1;
    }

    long len = cipher.size();
    unsigned char* pout = new unsigned char[len];
    memset(pout, 0, len);
    int cipher_len = Base64Decode(cipher, pout, len);

    EVP_CIPHER_CTX de_ctx;
    EVP_CIPHER_CTX_init(&de_ctx);
    EVP_DecryptInit_ex(&de_ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)strKey.c_str(), iv);
    unsigned char* pPlain = aes_decrypt(&de_ctx, pout, &cipher_len);
    plain = (char*)pPlain;

    free(pPlain);
    EVP_CIPHER_CTX_cleanup(&de_ctx);
    return 0;
}

unsigned char* CEncrypter::aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
    /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
    int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
    unsigned char *ciphertext = (unsigned char*)malloc(c_len);

    /* allows reusing of 'e' for multiple encryption cycles */
    EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

    /* update ciphertext, c_len is filled with the length of ciphertext generated,
    *len is the size of plaintext in bytes */
    EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

    /* update ciphertext with the final remaining bytes */
    EVP_EncryptFinal_ex(e, ciphertext + c_len, &f_len);

    *len = c_len + f_len;
    return ciphertext;
}

unsigned char* CEncrypter::aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
    /* plaintext will always be equal to or lesser than length of ciphertext*/
    int p_len = *len, f_len = 0;
    unsigned char *plaintext = (unsigned char*)malloc(p_len);

    EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
    EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
    EVP_DecryptFinal_ex(e, plaintext + p_len, &f_len);

    *len = p_len + f_len;
    return plaintext;
}