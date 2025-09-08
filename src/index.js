/**
 * OpenSSL.wasm - SIMD-optimized OpenSSL for WebAssembly
 * Provides automatic SIMD detection and fallback capability
 */

let opensslModule = null;
let simdSupported = null;

/**
 * Check if WASM SIMD is supported in the current environment
 */
function detectSIMDSupport() {
    if (simdSupported !== null) {
        return simdSupported;
    }

    try {
        // Check if WebAssembly.SIMD is available
        if (typeof WebAssembly !== 'undefined' && WebAssembly.validate) {
            // Test with a simple SIMD instruction (v128.const)
            const simdTest = new Uint8Array([
                0x00, 0x61, 0x73, 0x6d, // WASM magic
                0x01, 0x00, 0x00, 0x00, // version
                0x01, 0x05, 0x01, 0x60, // type section
                0x00, 0x01, 0x7b,       // () -> v128
                0x03, 0x02, 0x01, 0x00, // function section
                0x0a, 0x0a, 0x01, 0x08, // code section
                0x00, 0xfd, 0x0c,       // v128.const
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x0b // end
            ]);
            
            simdSupported = WebAssembly.validate(simdTest);
            console.log(`OpenSSL.wasm: SIMD support ${simdSupported ? 'detected' : 'not available'}`);
            return simdSupported;
        }
    } catch (e) {
        console.warn('OpenSSL.wasm: SIMD detection failed:', e.message);
    }
    
    simdSupported = false;
    return false;
}

/**
 * Load the appropriate OpenSSL WASM module based on SIMD support
 */
async function loadOpenSSLModule(basePath = './dist') {
    if (opensslModule) {
        return opensslModule;
    }

    const hasSimd = detectSIMDSupport();
    
    try {
        if (hasSimd) {
            console.log('OpenSSL.wasm: Loading SIMD-optimized version');
            const { default: OpenSSLSimd } = await import(`${basePath}/browser-simd/openssl-simd.js`);
            opensslModule = await OpenSSLSimd();
            
            // Verify SIMD is working in the module
            if (opensslModule._openssl_has_simd && opensslModule._openssl_has_simd() === 1) {
                console.log('OpenSSL.wasm: SIMD module loaded successfully');
                return opensslModule;
            } else {
                console.warn('OpenSSL.wasm: SIMD module loaded but SIMD not functional, falling back');
                opensslModule = null;
            }
        }
    } catch (e) {
        console.warn('OpenSSL.wasm: Failed to load SIMD version, falling back:', e.message);
        opensslModule = null;
    }
    
    // Load fallback version
    console.log('OpenSSL.wasm: Loading fallback version');
    try {
        const { default: OpenSSLFallback } = await import(`${basePath}/browser-fallback/openssl-fallback.js`);
        opensslModule = await OpenSSLFallback();
        console.log('OpenSSL.wasm: Fallback module loaded successfully');
        return opensslModule;
    } catch (e) {
        console.error('OpenSSL.wasm: Failed to load fallback version:', e);
        throw new Error('Failed to load any OpenSSL.wasm module');
    }
}

/**
 * OpenSSL.wasm API wrapper class
 */
class OpenSSL {
    constructor(module) {
        this.module = module;
        this._initWrappers();
    }

    _initWrappers() {
        // Initialize function wrappers
        this._init = this.module.cwrap('openssl_init', null, []);
        this._getVersion = this.module.cwrap('openssl_get_version', 'string', []);
        this._getVersionNumber = this.module.cwrap('openssl_get_version_number', 'number', []);
        this._randBytes = this.module.cwrap('openssl_rand_bytes', 'number', ['number', 'number']);
        this._sha256 = this.module.cwrap('openssl_sha256', 'number', ['number', 'number', 'number']);
        this._sha1 = this.module.cwrap('openssl_sha1', 'number', ['number', 'number', 'number']);
        this._md5 = this.module.cwrap('openssl_md5', 'number', ['number', 'number', 'number']);
        this._hmacSha256 = this.module.cwrap('openssl_hmac_sha256', 'number', ['number', 'number', 'number', 'number', 'number']);
        this._aesEncrypt = this.module.cwrap('openssl_aes_256_cbc_encrypt', 'number', ['number', 'number', 'number', 'number', 'number']);
        this._aesDecrypt = this.module.cwrap('openssl_aes_256_cbc_decrypt', 'number', ['number', 'number', 'number', 'number', 'number']);
        this._hasSimd = this.module.cwrap('openssl_has_simd', 'number', []);
        this._benchmarkSimd = this.module.cwrap('openssl_benchmark_simd', 'number', []);
        this._getError = this.module.cwrap('openssl_get_error', 'number', []);
        this._getErrorString = this.module.cwrap('openssl_get_error_string', 'string', ['number']);
        
        // Initialize OpenSSL
        this._init();
    }

    /**
     * Get OpenSSL version string
     */
    getVersion() {
        return this._getVersion();
    }

    /**
     * Get OpenSSL version number
     */
    getVersionNumber() {
        return this._getVersionNumber();
    }

    /**
     * Check if SIMD optimizations are available
     */
    hasSimd() {
        return this._hasSimd() === 1;
    }

    /**
     * Run SIMD performance benchmark
     * @returns {number} Benchmark time in milliseconds, or -1 if SIMD not available
     */
    benchmarkSimd() {
        return this._benchmarkSimd();
    }

    /**
     * Generate random bytes
     * @param {number} length - Number of random bytes to generate
     * @returns {Uint8Array} Array of random bytes
     */
    randomBytes(length) {
        const ptr = this.module._malloc(length);
        try {
            const result = this._randBytes(ptr, length);
            if (result !== 1) {
                throw new Error('Failed to generate random bytes');
            }
            return new Uint8Array(this.module.HEAPU8.buffer, ptr, length).slice();
        } finally {
            this.module._free(ptr);
        }
    }

    /**
     * Compute SHA-256 hash
     * @param {Uint8Array} data - Input data
     * @returns {Uint8Array} SHA-256 hash (32 bytes)
     */
    sha256(data) {
        const inputPtr = this.module._malloc(data.length);
        const outputPtr = this.module._malloc(32);
        
        try {
            this.module.HEAPU8.set(data, inputPtr);
            const result = this._sha256(inputPtr, data.length, outputPtr);
            
            if (result !== 32) {
                throw new Error('SHA-256 computation failed');
            }
            
            return new Uint8Array(this.module.HEAPU8.buffer, outputPtr, 32).slice();
        } finally {
            this.module._free(inputPtr);
            this.module._free(outputPtr);
        }
    }

    /**
     * Compute SHA-1 hash
     * @param {Uint8Array} data - Input data
     * @returns {Uint8Array} SHA-1 hash (20 bytes)
     */
    sha1(data) {
        const inputPtr = this.module._malloc(data.length);
        const outputPtr = this.module._malloc(20);
        
        try {
            this.module.HEAPU8.set(data, inputPtr);
            const result = this._sha1(inputPtr, data.length, outputPtr);
            
            if (result !== 20) {
                throw new Error('SHA-1 computation failed');
            }
            
            return new Uint8Array(this.module.HEAPU8.buffer, outputPtr, 20).slice();
        } finally {
            this.module._free(inputPtr);
            this.module._free(outputPtr);
        }
    }

    /**
     * Compute MD5 hash
     * @param {Uint8Array} data - Input data
     * @returns {Uint8Array} MD5 hash (16 bytes)
     */
    md5(data) {
        const inputPtr = this.module._malloc(data.length);
        const outputPtr = this.module._malloc(16);
        
        try {
            this.module.HEAPU8.set(data, inputPtr);
            const result = this._md5(inputPtr, data.length, outputPtr);
            
            if (result !== 16) {
                throw new Error('MD5 computation failed');
            }
            
            return new Uint8Array(this.module.HEAPU8.buffer, outputPtr, 16).slice();
        } finally {
            this.module._free(inputPtr);
            this.module._free(outputPtr);
        }
    }

    /**
     * Compute HMAC-SHA256
     * @param {Uint8Array} key - HMAC key
     * @param {Uint8Array} data - Input data
     * @returns {Uint8Array} HMAC-SHA256 (32 bytes)
     */
    hmacSha256(key, data) {
        const keyPtr = this.module._malloc(key.length);
        const dataPtr = this.module._malloc(data.length);
        const outputPtr = this.module._malloc(32);
        
        try {
            this.module.HEAPU8.set(key, keyPtr);
            this.module.HEAPU8.set(data, dataPtr);
            
            const result = this._hmacSha256(keyPtr, key.length, dataPtr, data.length, outputPtr);
            
            if (result !== 32) {
                throw new Error('HMAC-SHA256 computation failed');
            }
            
            return new Uint8Array(this.module.HEAPU8.buffer, outputPtr, 32).slice();
        } finally {
            this.module._free(keyPtr);
            this.module._free(dataPtr);
            this.module._free(outputPtr);
        }
    }

    /**
     * Encrypt data using AES-256-CBC
     * @param {Uint8Array} plaintext - Data to encrypt
     * @param {Uint8Array} key - AES key (32 bytes)
     * @param {Uint8Array} iv - Initialization vector (16 bytes)
     * @returns {Uint8Array} Encrypted data
     */
    aesEncrypt(plaintext, key, iv) {
        if (key.length !== 32) {
            throw new Error('AES-256 key must be 32 bytes');
        }
        if (iv.length !== 16) {
            throw new Error('AES IV must be 16 bytes');
        }
        
        const plaintextPtr = this.module._malloc(plaintext.length);
        const keyPtr = this.module._malloc(32);
        const ivPtr = this.module._malloc(16);
        const ciphertextPtr = this.module._malloc(plaintext.length + 16); // Extra space for padding
        
        try {
            this.module.HEAPU8.set(plaintext, plaintextPtr);
            this.module.HEAPU8.set(key, keyPtr);
            this.module.HEAPU8.set(iv, ivPtr);
            
            const result = this._aesEncrypt(plaintextPtr, plaintext.length, keyPtr, ivPtr, ciphertextPtr);
            
            if (result <= 0) {
                throw new Error('AES encryption failed');
            }
            
            return new Uint8Array(this.module.HEAPU8.buffer, ciphertextPtr, result).slice();
        } finally {
            this.module._free(plaintextPtr);
            this.module._free(keyPtr);
            this.module._free(ivPtr);
            this.module._free(ciphertextPtr);
        }
    }

    /**
     * Decrypt data using AES-256-CBC
     * @param {Uint8Array} ciphertext - Data to decrypt
     * @param {Uint8Array} key - AES key (32 bytes)
     * @param {Uint8Array} iv - Initialization vector (16 bytes)
     * @returns {Uint8Array} Decrypted data
     */
    aesDecrypt(ciphertext, key, iv) {
        if (key.length !== 32) {
            throw new Error('AES-256 key must be 32 bytes');
        }
        if (iv.length !== 16) {
            throw new Error('AES IV must be 16 bytes');
        }
        
        const ciphertextPtr = this.module._malloc(ciphertext.length);
        const keyPtr = this.module._malloc(32);
        const ivPtr = this.module._malloc(16);
        const plaintextPtr = this.module._malloc(ciphertext.length);
        
        try {
            this.module.HEAPU8.set(ciphertext, ciphertextPtr);
            this.module.HEAPU8.set(key, keyPtr);
            this.module.HEAPU8.set(iv, ivPtr);
            
            const result = this._aesDecrypt(ciphertextPtr, ciphertext.length, keyPtr, ivPtr, plaintextPtr);
            
            if (result <= 0) {
                throw new Error('AES decryption failed');
            }
            
            return new Uint8Array(this.module.HEAPU8.buffer, plaintextPtr, result).slice();
        } finally {
            this.module._free(ciphertextPtr);
            this.module._free(keyPtr);
            this.module._free(ivPtr);
            this.module._free(plaintextPtr);
        }
    }

    /**
     * Get last OpenSSL error
     * @returns {string} Error string
     */
    getLastError() {
        const error = this._getError();
        if (error === 0) {
            return null;
        }
        return this._getErrorString(error);
    }
}

/**
 * Initialize OpenSSL.wasm with automatic SIMD detection
 * @param {string} basePath - Base path for WASM modules
 * @returns {Promise<OpenSSL>} OpenSSL instance
 */
export async function initOpenSSL(basePath) {
    const module = await loadOpenSSLModule(basePath);
    return new OpenSSL(module);
}

/**
 * Check if SIMD is supported without initializing the full module
 * @returns {boolean} True if SIMD is supported
 */
export function isSimdSupported() {
    return detectSIMDSupport();
}

export default { initOpenSSL, isSimdSupported };