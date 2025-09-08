#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <emscripten/emscripten.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// WASM-exported functions for OpenSSL cryptographic operations

EMSCRIPTEN_KEEPALIVE
void openssl_init(void) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

EMSCRIPTEN_KEEPALIVE
const char* openssl_get_version(void) {
    return OpenSSL_version(OPENSSL_VERSION);
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
    return RAND_pseudo_bytes(buf, num);
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

// SIMD compatibility stubs for fallback build
EMSCRIPTEN_KEEPALIVE
int openssl_has_simd(void) {
    return 0; // SIMD not available in fallback build
}

EMSCRIPTEN_KEEPALIVE
int openssl_benchmark_simd(void) {
    return -1; // SIMD benchmark not available in fallback build
}