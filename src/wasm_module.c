#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <emscripten/emscripten.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// OpenSSL initialization and cleanup
EMSCRIPTEN_KEEPALIVE
int openssl_init_crypto(void) {
    return OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
}

EMSCRIPTEN_KEEPALIVE
int openssl_init_ssl(void) {
    return OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
}

EMSCRIPTEN_KEEPALIVE
void openssl_cleanup(void) {
    OPENSSL_cleanup();
}

EMSCRIPTEN_KEEPALIVE
const char* openssl_get_version(void) {
    return OPENSSL_VERSION_TEXT;
}

EMSCRIPTEN_KEEPALIVE
unsigned long openssl_get_version_number(void) {
    return OpenSSL_version_num();
}

// Random number generation
EMSCRIPTEN_KEEPALIVE
int openssl_rand_bytes(unsigned char* buf, int num) {
    return RAND_bytes(buf, num);
}

EMSCRIPTEN_KEEPALIVE
int openssl_rand_pseudo_bytes(unsigned char* buf, int num) {
    // RAND_pseudo_bytes was deprecated in OpenSSL 3.0
    // Use RAND_bytes for cryptographically secure random numbers
    return RAND_bytes(buf, num);
}

// SHA-256 hashing
EMSCRIPTEN_KEEPALIVE
int openssl_sha256(const unsigned char* input, size_t input_len, unsigned char* output) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    
    if (EVP_DigestUpdate(ctx, input, input_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    
    unsigned int output_len;
    if (EVP_DigestFinal_ex(ctx, output, &output_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    
    EVP_MD_CTX_free(ctx);
    return output_len;
}

// SHA-1 hashing
EMSCRIPTEN_KEEPALIVE
int openssl_sha1(const unsigned char* input, size_t input_len, unsigned char* output) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    
    if (EVP_DigestInit_ex(ctx, EVP_sha1(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    
    if (EVP_DigestUpdate(ctx, input, input_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    
    unsigned int output_len;
    if (EVP_DigestFinal_ex(ctx, output, &output_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    
    EVP_MD_CTX_free(ctx);
    return output_len;
}

// MD5 hashing
EMSCRIPTEN_KEEPALIVE
int openssl_md5(const unsigned char* input, size_t input_len, unsigned char* output) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    
    if (EVP_DigestInit_ex(ctx, EVP_md5(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    
    if (EVP_DigestUpdate(ctx, input, input_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    
    unsigned int output_len;
    if (EVP_DigestFinal_ex(ctx, output, &output_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    
    EVP_MD_CTX_free(ctx);
    return output_len;
}

// HMAC-SHA256
EMSCRIPTEN_KEEPALIVE
int openssl_hmac_sha256(const unsigned char* key, int key_len, 
                        const unsigned char* data, size_t data_len, 
                        unsigned char* output) {
    unsigned int output_len;
    unsigned char* result = HMAC(EVP_sha256(), key, key_len, data, data_len, output, &output_len);
    return result ? output_len : 0;
}

// AES-256-CBC encryption
EMSCRIPTEN_KEEPALIVE
int openssl_aes_256_cbc_encrypt(const unsigned char* plaintext, int plaintext_len,
                                 const unsigned char* key, const unsigned char* iv,
                                 unsigned char* ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    int len;
    int ciphertext_len;
    
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// AES-256-CBC decryption
EMSCRIPTEN_KEEPALIVE
int openssl_aes_256_cbc_decrypt(const unsigned char* ciphertext, int ciphertext_len,
                                 const unsigned char* key, const unsigned char* iv,
                                 unsigned char* plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    int len;
    int plaintext_len;
    
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len = len;
    
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

// RSA key generation (simplified)
EMSCRIPTEN_KEEPALIVE
int openssl_rsa_generate_key(int bits, unsigned char* public_key_der, int* public_key_len,
                             unsigned char* private_key_der, int* private_key_len) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) return 0;
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    
    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    
    // Extract public key
    unsigned char* pub_der = public_key_der;
    *public_key_len = i2d_PUBKEY(pkey, &pub_der);
    
    // Extract private key
    unsigned char* priv_der = private_key_der;
    *private_key_len = i2d_PrivateKey(pkey, &priv_der);
    
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    
    return (*public_key_len > 0 && *private_key_len > 0) ? 1 : 0;
}

// Get last error
EMSCRIPTEN_KEEPALIVE
unsigned long openssl_get_error(void) {
    return ERR_get_error();
}

EMSCRIPTEN_KEEPALIVE
const char* openssl_get_error_string(unsigned long error) {
    return ERR_error_string(error, NULL);
}

// Generic hash function (supports multiple algorithms)
EMSCRIPTEN_KEEPALIVE
int openssl_hash_standard(const unsigned char* data, size_t data_len, const char* algorithm, unsigned char* output) {
    if (!data || !algorithm || !output) {
        return 0;
    }

    const EVP_MD* md = NULL;
    if (strcmp(algorithm, "SHA256") == 0) {
        md = EVP_sha256();
    } else if (strcmp(algorithm, "SHA512") == 0) {
        md = EVP_sha512();
    } else if (strcmp(algorithm, "MD5") == 0) {
        md = EVP_md5();
    } else if (strcmp(algorithm, "SHA1") == 0) {
        md = EVP_sha1();
    } else {
        return 0;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;

    int result = 0;
    if (EVP_DigestInit_ex(ctx, md, NULL) == 1 &&
        EVP_DigestUpdate(ctx, data, data_len) == 1 &&
        EVP_DigestFinal_ex(ctx, output, NULL) == 1) {
        result = 1;
    }

    EVP_MD_CTX_free(ctx);
    return result;
}

// Generic AES encryption
EMSCRIPTEN_KEEPALIVE
int openssl_aes_encrypt_standard(const unsigned char* data, size_t data_len,
                               const unsigned char* key, const char* mode,
                               unsigned char* output) {
    if (!data || !key || !mode || !output) {
        return 0;
    }

    const EVP_CIPHER* cipher = NULL;
    if (strcmp(mode, "GCM") == 0) {
        cipher = EVP_aes_256_gcm();
    } else if (strcmp(mode, "CBC") == 0) {
        cipher = EVP_aes_256_cbc();
    } else {
        return 0;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return 0;

    unsigned char iv[16];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    int len = 0, total_len = 0;

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }

    // Copy IV to output first
    memcpy(output, iv, 16);
    total_len += 16;

    if (EVP_EncryptUpdate(ctx, output + total_len, &len, data, data_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    total_len += len;

    if (EVP_EncryptFinal_ex(ctx, output + total_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    total_len += len;

    // For GCM mode, append the authentication tag
    if (strcmp(mode, "GCM") == 0) {
        unsigned char tag[16];
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        memcpy(output + total_len, tag, 16);
        total_len += 16;
    }

    EVP_CIPHER_CTX_free(ctx);
    return total_len;
}

// RSA verification
EMSCRIPTEN_KEEPALIVE
int openssl_rsa_verify_standard(const unsigned char* data, size_t data_len,
                              const unsigned char* signature, size_t sig_len,
                              const unsigned char* public_key) {
    if (!data || !signature || !public_key) {
        return 0;
    }

    BIO* bio = BIO_new_mem_buf(public_key, -1);
    if (!bio) return 0;

    EVP_PKEY* pkey = d2i_PUBKEY_bio(bio, NULL);
    BIO_free(bio);
    if (!pkey) return 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        return 0;
    }

    int result = 0;
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) == 1 &&
        EVP_DigestVerifyUpdate(ctx, data, data_len) == 1 &&
        EVP_DigestVerifyFinal(ctx, signature, sig_len) == 1) {
        result = 1;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return result;
}

// EC point multiplication
EMSCRIPTEN_KEEPALIVE
int openssl_ec_point_mul_standard(const unsigned char* point,
                                const unsigned char* scalar,
                                unsigned char* result) {
    if (!point || !scalar || !result) {
        return 0;
    }

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group) return 0;

    EC_POINT* ec_point = EC_POINT_new(group);
    if (!ec_point) {
        EC_GROUP_free(group);
        return 0;
    }

    BIGNUM* bn_scalar = BN_bin2bn(scalar, 32, NULL);
    if (!bn_scalar) {
        EC_POINT_free(ec_point);
        EC_GROUP_free(group);
        return 0;
    }

    if (EC_POINT_oct2point(group, ec_point, point, 65, NULL) != 1) {
        BN_free(bn_scalar);
        EC_POINT_free(ec_point);
        EC_GROUP_free(group);
        return 0;
    }

    EC_POINT* result_point = EC_POINT_new(group);
    if (!result_point) {
        BN_free(bn_scalar);
        EC_POINT_free(ec_point);
        EC_GROUP_free(group);
        return 0;
    }

    int success = 0;
    if (EC_POINT_mul(group, result_point, NULL, ec_point, bn_scalar, NULL) == 1) {
        size_t result_len = EC_POINT_point2oct(group, result_point,
                                             POINT_CONVERSION_UNCOMPRESSED,
                                             result, 65, NULL);
        success = (result_len == 65) ? 1 : 0;
    }

    EC_POINT_free(result_point);
    BN_free(bn_scalar);
    EC_POINT_free(ec_point);
    EC_GROUP_free(group);
    return success;
}

// SIMD compatibility stubs for fallback build
EMSCRIPTEN_KEEPALIVE
int openssl_has_simd(void) {
    return 0; // SIMD not available in fallback build
}

EMSCRIPTEN_KEEPALIVE
int openssl_benchmark_simd(void) {
    return -1; // SIMD benchmark not available in fallback build
}