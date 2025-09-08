// OpenSSL WASM-Native TypeScript Definitions
// Copyright 2025 Superstruct Ltd, New Zealand. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License"). You may not use
// this file except in compliance with the License. You can obtain a copy
// in the file LICENSE.txt in the source distribution or at
// https://www.openssl.org/source/license.html
//
// Security-first design with comprehensive type coverage

export interface OpenSSLWASMNativeOptions {
    // File system configuration
    persistentCache?: boolean;
    asyncLoading?: boolean;
    cdnSupport?: boolean;
    
    // Security configuration
    encryptClientCerts?: boolean;
    persistentPrivateKeys?: false; // Always false for security
    verifyCertificateIntegrity?: boolean;
    
    // Performance configuration
    maxCacheSize?: number;
    maxCacheAge?: number;
    sessionTimeout?: number;
    sessionEncryptionKey?: CryptoKey | null;
    
    // Trusted sources
    trustedCdnSources?: string[];
    
    // Directory configuration
    directories?: {
        system: string;
        cache: string;
        temp: string;
        packages: string;
        remote: string;
    };
}

export interface CertificateLoadOptions {
    expectedHash?: string;
    isCABundle?: boolean;
    algorithm?: 'SHA-256' | 'SHA-512';
}

export interface CertificateInfo {
    id: string;
    loaded: boolean;
    size: number;
    loadedAt: number;
    options?: CertificateLoadOptions;
}

export interface CertificateMetadata extends CertificateInfo {
    ptr?: number;
    path?: string;
    cached?: {
        url: string;
        loadedAt: number;
        integrityHash: string;
    } | null;
}

export interface CacheEntry {
    data: Uint8Array;
    url?: string;
    loadedAt: number;
    hash?: string;
}

export interface SessionData {
    sessionId: string;
    data: Uint8Array;
    timestamp: number;
    encrypted: boolean;
}

export interface InitializationResult {
    success: boolean;
    error?: string;
    features?: EnabledFeatures;
}

export interface EnabledFeatures {
    persistentCache: boolean;
    asyncLoading: boolean;
    cdnSupport: boolean;
    encryptClientCerts: boolean;
    verifyCertificateIntegrity: boolean;
    sessionCache: boolean;
    privateKeyManager: boolean;
}

export declare class OpenSSLWASMNative {
    readonly module: any;
    readonly FS: any;
    readonly ccall: Function;
    readonly cwrap: Function;
    
    readonly config: OpenSSLWASMNativeOptions;
    readonly initialized: boolean;
    
    readonly privateKeyManager: SecurePrivateKeyManager;
    readonly certificateCache: IntelligentCertificateCache;
    readonly sessionCache: SecureSSLSessionCache;
    
    readonly loadedCertificates: Map<string, CertificateMetadata>;
    readonly activeSessions: Map<string, SessionData>;
    
    constructor(module: any);
    
    /**
     * Initialize OpenSSL WASM-Native with optional configuration
     */
    initialize(options?: OpenSSLWASMNativeOptions): Promise<InitializationResult>;
    
    /**
     * Load certificate from memory buffer
     */
    loadCertificateFromBuffer(
        buffer: ArrayBuffer | Uint8Array, 
        certificateId: string,
        options?: CertificateLoadOptions
    ): Promise<string>;
    
    /**
     * Load certificate from URL with integrity verification
     */
    loadCertificateFromUrl(
        url: string,
        certificateId: string,
        options?: CertificateLoadOptions
    ): Promise<string>;
    
    /**
     * Load certificate from file system path
     */
    loadCertificateFromPath(
        certPath: string,
        certificateId: string
    ): Promise<string>;
    
    /**
     * Load CA bundle from trusted CDN provider
     */
    loadCABundleFromCDN(
        provider: 'mozilla' | 'curl' | string,
        bundleName?: string
    ): Promise<string>;
    
    /**
     * Load certificate package (collection of certificates)
     */
    loadCertificatePackage(
        packageUrl: string,
        packageName: string,
        options?: CertificateLoadOptions
    ): Promise<string[]>;
    
    /**
     * Verify certificate validity using OpenSSL
     */
    verifyCertificateValidity(certPath: string): Promise<boolean>;
    
    /**
     * Verify data integrity using Web Crypto API
     */
    verifyDataIntegrity(
        data: Uint8Array,
        expectedHash: string,
        algorithm?: 'SHA-256' | 'SHA-512'
    ): Promise<boolean>;
    
    /**
     * Get information about loaded certificate
     */
    getCertificateInfo(certificateId: string): CertificateMetadata | null;
    
    /**
     * List all loaded certificates
     */
    listLoadedCertificates(): CertificateInfo[];
    
    /**
     * Get currently enabled features
     */
    getEnabledFeatures(): EnabledFeatures;
    
    /**
     * Clean up resources and perform secure deletion
     */
    cleanup(): void;
    
    // OpenSSL function wrappers
    private initializeFunctions(): void;
    private loadDefaultCABundle(): Promise<void>;
    private logEnabledFeatures(): void;
}

export declare class SecurePrivateKeyManager {
    readonly FS: any;
    readonly activeKeys: Map<string, PrivateKeyInfo>;
    
    constructor(FS: any);
    
    /**
     * Store private key in memory-only storage (NEVER persistent)
     */
    storePrivateKey(
        keyId: string,
        keyData: ArrayBuffer | Uint8Array,
        passphrase?: string | null
    ): string;
    
    /**
     * Get path to stored private key
     */
    getPrivateKeyPath(keyId: string): string | null;
    
    /**
     * Securely remove private key with overwrite
     */
    removePrivateKey(keyId: string): void;
    
    /**
     * Clean up all private keys
     */
    cleanup(): void;
}

export interface PrivateKeyInfo {
    path: string;
    created: number;
    passphrase?: string | null;
}

export declare class IntelligentCertificateCache {
    readonly FS: any;
    readonly config: OpenSSLWASMNativeOptions;
    readonly memoryCache: Map<string, CacheEntry>;
    readonly maxSize: number;
    readonly maxAge: number;
    
    persistentEnabled: boolean;
    
    constructor(FS: any, config: OpenSSLWASMNativeOptions);
    
    /**
     * Initialize cache system
     */
    initialize(): Promise<void>;
    
    /**
     * Get cached certificate
     */
    get(key: string): Promise<CacheEntry | null>;
    
    /**
     * Store certificate in cache
     */
    set(key: string, value: CacheEntry): Promise<void>;
    
    /**
     * Check if cache entry is expired
     */
    isExpired(cached: CacheEntry): boolean;
    
    /**
     * Enforce cache size limits
     */
    private enforceSizeLimits(): Promise<void>;
}

export declare class SecureSSLSessionCache {
    readonly FS: any;
    readonly config: OpenSSLWASMNativeOptions;
    readonly memoryCache: Map<string, SessionCacheEntry>;
    
    encryptionKey: CryptoKey | null;
    enabled: boolean;
    
    constructor(FS: any, config: OpenSSLWASMNativeOptions);
    
    /**
     * Initialize session cache with optional encryption
     */
    initialize(encryptionKey?: CryptoKey | null): Promise<void>;
    
    /**
     * Check if session caching is enabled
     */
    isEnabled(): boolean;
    
    /**
     * Store SSL session data
     */
    storeSession(sessionId: string, sessionData: Uint8Array): Promise<void>;
    
    /**
     * Load SSL session data
     */
    loadSession(sessionId: string): Promise<Uint8Array | null>;
    
    /**
     * Check if session is expired
     */
    isSessionExpired(cached: SessionCacheEntry): boolean;
    
    /**
     * Clean up session cache
     */
    cleanup(): void;
    
    // Encryption methods (private)
    private encryptSessionData(sessionData: Uint8Array): Promise<Uint8Array>;
    private decryptSessionData(encryptedData: Uint8Array): Promise<Uint8Array>;
}

export interface SessionCacheEntry {
    data: Uint8Array;
    timestamp: number;
}

// CDN Provider configurations
export interface CDNProvider {
    name: string;
    url: string;
    hash?: string;
    trustedDomain: string;
}

// Security configurations
export interface SecurityConfig {
    persistentPrivateKeys: false; // Always false
    encryptClientCerts: boolean;
    verifyCertificateIntegrity: boolean;
    maxCacheAge: number;
    trustedCdnSources: string[];
}

// Error types
export class OpenSSLError extends Error {
    constructor(message: string, public code?: string) {
        super(message);
        this.name = 'OpenSSLError';
    }
}

export class CertificateError extends OpenSSLError {
    constructor(message: string, public certificateId?: string) {
        super(message, 'CERT_ERROR');
        this.name = 'CertificateError';
    }
}

export class SecurityError extends OpenSSLError {
    constructor(message: string, public securityViolation?: string) {
        super(message, 'SECURITY_ERROR');
        this.name = 'SecurityError';
    }
}

// Module factory function
export declare function createOpenSSLWASMNative(
    module: any,
    options?: OpenSSLWASMNativeOptions
): Promise<OpenSSLWASMNative>;

// Default export
export default OpenSSLWASMNative;