/**
 * OpenSSL WASM TypeScript Definitions
 *
 * Comprehensive type coverage for cryptographic operations
 * with SIMD optimization support.
 *
 * Copyright 2025 Superstruct Ltd, New Zealand
 * Licensed under Apache-2.0
 */

/**
 * OpenSSL initialization configuration
 */
export interface OpenSSLConfig {
  /** Enable verbose logging during initialization */
  verbose?: boolean;
  /** Maximum memory allocation in bytes */
  maxMemory?: number;
  /** Enable threading support (when available) */
  enableThreading?: boolean;
  /** Custom entropy source for random number generation */
  entropySource?: Uint8Array;
}

/**
 * Hash computation result
 */
export interface HashResult {
  /** Hash algorithm used */
  algorithm: 'SHA256' | 'SHA512' | 'MD5' | 'SHA1';
  /** Raw hash bytes */
  hash: Uint8Array;
  /** Hex-encoded hash string */
  hexHash: string;
  /** Whether SIMD optimization was used */
  simdUsed: boolean;
}

/**
 * Symmetric cipher operation result
 */
export interface CipherResult {
  /** Cipher algorithm and mode used */
  algorithm: string;
  /** Encrypted/decrypted data */
  data: Uint8Array;
  /** IV used (for modes that require it) */
  iv?: Uint8Array;
  /** Authentication tag (for AEAD modes) */
  tag?: Uint8Array;
  /** Whether SIMD optimization was used */
  simdUsed: boolean;
}

/**
 * Signature verification result
 */
export interface VerifyResult {
  /** Whether the signature is valid */
  valid: boolean;
  /** Signature algorithm used */
  algorithm: 'RSA' | 'ECDSA' | 'EdDSA';
  /** Whether SIMD optimization was used */
  simdUsed: boolean;
  /** Error message if verification failed */
  error?: string | undefined;
}

/**
 * Digital signature result
 */
export interface SignResult {
  /** Signature bytes */
  signature: Uint8Array;
  /** Signature algorithm used */
  algorithm: 'RSA' | 'ECDSA' | 'EdDSA';
  /** Whether SIMD optimization was used */
  simdUsed: boolean;
}

/**
 * RSA key pair
 */
export interface RSAKeyPair {
  /** Public key in DER format */
  publicKey: Uint8Array;
  /** Private key in DER format */
  privateKey: Uint8Array;
  /** Key size in bits */
  keySize: number;
  /** Public exponent */
  exponent: number;
}

/**
 * Elliptic curve key pair
 */
export interface ECKeyPair {
  /** Public key in DER format */
  publicKey: Uint8Array;
  /** Private key in DER format */
  privateKey: Uint8Array;
  /** Curve name (e.g., 'P-256', 'P-384', 'P-521') */
  curve: string;
}

/**
 * X.509 certificate information
 */
export interface CertificateInfo {
  /** Certificate in DER format */
  certificate: Uint8Array;
  /** Subject distinguished name */
  subject: string;
  /** Issuer distinguished name */
  issuer: string;
  /** Serial number (hex string) */
  serialNumber: string;
  /** Valid not before timestamp */
  notBefore: Date;
  /** Valid not after timestamp */
  notAfter: Date;
  /** Public key algorithm */
  publicKeyAlgorithm: string;
  /** Signature algorithm */
  signatureAlgorithm: string;
  /** Certificate fingerprint (SHA-256) */
  fingerprint: string;
}

/**
 * TLS/SSL context configuration
 */
export interface SSLConfig {
  /** Minimum TLS version */
  minVersion?: 'TLSv1.2' | 'TLSv1.3';
  /** Maximum TLS version */
  maxVersion?: 'TLSv1.2' | 'TLSv1.3';
  /** Cipher suites to use */
  cipherSuites?: string[];
  /** Certificate chain */
  certificateChain?: Uint8Array[];
  /** Private key */
  privateKey?: Uint8Array;
  /** CA certificates for peer verification */
  caCertificates?: Uint8Array[];
  /** Enable client certificate verification */
  verifyPeer?: boolean;
}

/**
 * Random number generation options
 */
export interface RandomOptions {
  /** Number of random bytes to generate */
  length: number;
  /** Use cryptographically secure random (default: true) */
  secure?: boolean;
  /** Custom entropy source */
  entropySource?: Uint8Array;
}

/**
 * Key derivation function options
 */
export interface KDFOptions {
  /** Password/key material */
  password: Uint8Array;
  /** Salt */
  salt: Uint8Array;
  /** Number of iterations */
  iterations: number;
  /** Derived key length */
  keyLength: number;
  /** Hash algorithm to use */
  hash?: 'SHA256' | 'SHA512';
}

/**
 * HMAC computation options
 */
export interface HMACOptions {
  /** Data to authenticate */
  data: Uint8Array;
  /** Secret key */
  key: Uint8Array;
  /** Hash algorithm */
  algorithm?: 'SHA256' | 'SHA512' | 'SHA1';
}

/**
 * Performance benchmark result
 */
export interface BenchmarkResult {
  /** Operation name */
  operation: string;
  /** Data size in bytes */
  dataSize: number;
  /** Operations per second */
  opsPerSecond: number;
  /** Throughput in MB/s */
  throughputMBs: number;
  /** Average latency in microseconds */
  avgLatencyUs: number;
  /** Whether SIMD was used */
  simdUsed: boolean;
  /** Speedup factor over non-SIMD (if applicable) */
  simdSpeedupFactor?: number;
}

/**
 * Error types that can be thrown by OpenSSL operations
 */
export class OpenSSLError extends Error {
  constructor(
    message: string,
    public readonly code?: number,
    public readonly operation?: string
  ) {
    super(message);
    this.name = 'OpenSSLError';
  }
}

/**
 * SIMD optimization status
 */
export interface SIMDStatus {
  /** Whether SIMD is supported by the browser */
  browserSupport: boolean;
  /** Whether SIMD is enabled in the OpenSSL build */
  buildSupport: boolean;
  /** Whether SIMD is currently active */
  active: boolean;
  /** SIMD instruction set detected */
  instructionSet?: 'WASM_SIMD128';
}

/**
 * Memory usage statistics
 */
export interface MemoryStats {
  /** Current memory usage in bytes */
  used: number;
  /** Total allocated memory in bytes */
  total: number;
  /** Peak memory usage in bytes */
  peak: number;
  /** Number of allocations */
  allocations: number;
  /** Number of deallocations */
  deallocations: number;
}

/**
 * OpenSSL feature availability
 */
export interface FeatureSupport {
  /** Hash algorithms */
  hash: {
    md5: boolean;
    sha1: boolean;
    sha256: boolean;
    sha512: boolean;
    sha3: boolean;
  };
  /** Symmetric ciphers */
  cipher: {
    aes: boolean;
    chacha20: boolean;
    des: boolean;
  };
  /** Asymmetric algorithms */
  asymmetric: {
    rsa: boolean;
    ecdsa: boolean;
    eddsa: boolean;
    dh: boolean;
  };
  /** Key derivation */
  kdf: {
    pbkdf2: boolean;
    scrypt: boolean;
    argon2: boolean;
  };
  /** TLS/SSL */
  tls: {
    v12: boolean;
    v13: boolean;
    dtls: boolean;
  };
  /** Advanced features */
  advanced: {
    simd: boolean;
    threading: boolean;
    asm: boolean;
  };
}