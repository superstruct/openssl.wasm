// OpenSSL WASM-Native JavaScript API
// 
// WASM Integration Copyright (c) 2025 Superstruct Ltd, New Zealand
// Licensed under the same license as the underlying OpenSSL project (Apache License 2.0)
//
// You can obtain a copy of the License in the file LICENSE.txt in the source 
// distribution or at https://www.openssl.org/source/license.html
//
// Security-first design with IDBFS persistence, async loading, and certificate management
// Advanced WASM-native JavaScript API for OpenSSL

class OpenSSLWASMNative {
    constructor(module) {
        this.module = module;
        this.FS = module.FS;
        this.ccall = module.ccall;
        this.cwrap = module.cwrap;
        
        // Configuration from pre-init
        this.config = window.OpenSSL_WASM_NATIVE_CONFIG || {
            persistentCache: false,
            asyncLoading: false,
            directories: {
                system: '/ssl-system',
                cache: '/ssl-cache', 
                temp: '/ssl-temp',
                packages: '/ssl-packages',
                remote: '/ssl-remote'
            }
        };
        
        // Initialize core OpenSSL functions
        this.initializeFunctions();
        
        // Security managers
        this.privateKeyManager = new SecurePrivateKeyManager(this.FS);
        this.certificateCache = new IntelligentCertificateCache(this.FS, this.config);
        this.sessionCache = new SecureSSLSessionCache(this.FS, this.config);
        
        // State tracking
        this.initialized = false;
        this.loadedCertificates = new Map();
        this.activeSessions = new Map();
        
        console.log('🔐 OpenSSL WASM-Native instance created');
    }
    
    initializeFunctions() {
        // Core OpenSSL initialization
        this.openssl_init_crypto = this.cwrap('OPENSSL_init_crypto', 'number', ['number', 'number']);
        this.openssl_init_ssl = this.cwrap('OPENSSL_init_ssl', 'number', ['number', 'number']);
        this.openssl_cleanup = this.cwrap('OPENSSL_cleanup', null, []);
        
        // Certificate functions
        this.x509_new = this.cwrap('X509_new', 'number', []);
        this.x509_free = this.cwrap('X509_free', null, ['number']);
        this.x509_verify_cert = this.cwrap('X509_verify_cert', 'number', ['number']);
        this.x509_load_cert_file = this.cwrap('X509_load_cert_file', 'number', ['string', 'number']);
        
        // Certificate store functions
        this.x509_store_new = this.cwrap('X509_STORE_new', 'number', []);
        this.x509_store_free = this.cwrap('X509_STORE_free', null, ['number']);
        this.x509_store_add_cert = this.cwrap('X509_STORE_add_cert', 'number', ['number', 'number']);
        this.x509_store_load_locations = this.cwrap('X509_STORE_load_locations', 'number', ['number', 'string', 'string']);
        
        // SSL context functions
        this.ssl_ctx_new = this.cwrap('SSL_CTX_new', 'number', ['number']);
        this.ssl_ctx_free = this.cwrap('SSL_CTX_free', null, ['number']);
        this.ssl_ctx_load_verify_locations = this.cwrap('SSL_CTX_load_verify_locations', 'number', ['number', 'string', 'string']);
        
        // Error handling
        this.err_get_error = this.cwrap('ERR_get_error', 'number', []);
        this.err_error_string = this.cwrap('ERR_error_string', 'string', ['number', 'number']);
        
        console.log('✅ OpenSSL functions initialized');
    }
    
    async initialize(options = {}) {
        console.log('🚀 Initializing OpenSSL WASM-Native...');
        
        // Merge options with config
        Object.assign(this.config, options);
        
        try {
            // Initialize OpenSSL library
            const cryptoResult = this.openssl_init_crypto(0, 0);
            const sslResult = this.openssl_init_ssl(0, 0);
            
            if (cryptoResult !== 1 || sslResult !== 1) {
                throw new Error('OpenSSL initialization failed');
            }
            
            // Initialize certificate cache
            await this.certificateCache.initialize();
            
            // Initialize session cache if encryption key provided
            if (options.sessionEncryptionKey) {
                await this.sessionCache.initialize(options.sessionEncryptionKey);
            }
            
            // Load default CA bundle if available
            await this.loadDefaultCABundle();
            
            this.initialized = true;
            console.log('✅ OpenSSL WASM-Native initialization complete');
            
            // Log enabled features
            this.logEnabledFeatures();
            
            return {
                success: true,
                features: this.getEnabledFeatures()
            };
            
        } catch (error) {
            console.error('🚨 OpenSSL initialization failed:', error);
            return {
                success: false,
                error: error.message
            };
        }
    }
    
    async loadDefaultCABundle() {
        const bundlePath = `${this.config.directories.system}/ca-bundle.crt`;
        
        if (this.FS.analyzePath(bundlePath).exists) {
            console.log('📋 Loading default CA bundle...');
            try {
                await this.loadCertificateFromPath(bundlePath, 'default-ca-bundle');
                console.log('✅ Default CA bundle loaded');
            } catch (error) {
                console.warn('⚠️ Failed to load default CA bundle:', error);
            }
        } else {
            console.log('📝 No default CA bundle found, certificates can be loaded manually');
        }
    }
    
    async loadCertificateFromBuffer(buffer, certificateId, options = {}) {
        console.log(`📜 Loading certificate: ${certificateId}`);
        
        try {
            // Validate input
            if (!buffer || buffer.length === 0) {
                throw new Error('Invalid certificate buffer');
            }
            
            // Write to temporary file
            const tempPath = `${this.config.directories.temp}/${certificateId}.crt`;
            this.FS.writeFile(tempPath, new Uint8Array(buffer));
            
            // Verify certificate validity if required
            if (this.config.verifyCertificateIntegrity) {
                const isValid = await this.verifyCertificateValidity(tempPath);
                if (!isValid) {
                    this.FS.unlink(tempPath);
                    throw new Error('Certificate validation failed');
                }
            }
            
            // Load certificate with OpenSSL
            const certPtr = this.x509_load_cert_file(tempPath, 1); // PEM format
            if (certPtr === 0) {
                this.FS.unlink(tempPath);
                throw new Error('OpenSSL certificate loading failed');
            }
            
            // Store certificate metadata
            this.loadedCertificates.set(certificateId, {
                id: certificateId,
                ptr: certPtr,
                path: tempPath,
                loaded: true,
                size: buffer.length,
                loadedAt: Date.now(),
                options: options
            });
            
            console.log(`✅ Certificate loaded: ${certificateId}`);
            return certificateId;
            
        } catch (error) {
            console.error(`🚨 Failed to load certificate ${certificateId}:`, error);
            throw error;
        }
    }
    
    async loadCertificateFromUrl(url, certificateId, options = {}) {
        console.log(`🌐 Loading certificate from URL: ${url}`);
        
        // Verify trusted source
        if (this.config.trustedCdnSources && this.config.trustedCdnSources.length > 0) {
            const urlDomain = new URL(url).hostname;
            const isTrusted = this.config.trustedCdnSources.some(trusted => 
                trusted === '*' || urlDomain.includes(trusted)
            );
            
            if (!isTrusted) {
                throw new Error(`Untrusted certificate source: ${urlDomain}`);
            }
        }
        
        // Check cache first
        const cached = await this.certificateCache.get(certificateId);
        if (cached) {
            console.log(`📋 Loading certificate from cache: ${certificateId}`);
            return this.loadCertificateFromBuffer(cached.data, certificateId, options);
        }
        
        // Download asynchronously
        return new Promise((resolve, reject) => {
            const onLoad = async (response) => {
                try {
                    const certData = new Uint8Array(response);
                    
                    // Verify integrity if hash provided
                    if (options.expectedHash) {
                        const isValid = await this.verifyDataIntegrity(certData, options.expectedHash);
                        if (!isValid) {
                            reject(new Error('Certificate integrity verification failed'));
                            return;
                        }
                    }
                    
                    // Cache for future use
                    await this.certificateCache.set(certificateId, {
                        data: certData,
                        url: url,
                        loadedAt: Date.now(),
                        hash: options.expectedHash
                    });
                    
                    // Load certificate
                    const result = await this.loadCertificateFromBuffer(certData, certificateId, options);
                    resolve(result);
                    
                } catch (error) {
                    reject(error);
                }
            };
            
            const onError = (error) => {
                reject(new Error(`Failed to download certificate: ${error}`));
            };
            
            this.module.ccall('emscripten_async_wget_data', null,
                ['string', 'number', 'number'],
                [url, onLoad, onError]
            );
        });
    }
    
    async loadCABundleFromCDN(provider, bundleName = 'ca-bundle') {
        console.log(`📦 Loading CA bundle from ${provider}`);
        
        const cdnProviders = {
            'mozilla': {
                url: 'https://curl.se/ca/cacert.pem',
                hash: null // Hash should be fetched from a trusted source
            },
            'curl': {
                url: 'https://curl.se/ca/cacert.pem', 
                hash: null
            },
            'custom': {
                url: provider, // Allow custom URLs
                hash: null
            }
        };
        
        const providerConfig = cdnProviders[provider] || cdnProviders['custom'];
        
        return this.loadCertificateFromUrl(providerConfig.url, bundleName, {
            expectedHash: providerConfig.hash,
            isCABundle: true
        });
    }
    
    async loadCertificatePackage(packageUrl, packageName, options = {}) {
        console.log(`📦 Loading certificate package: ${packageName}`);
        
        const packagePath = `${this.config.directories.packages}/${packageName}`;
        
        try {
            // Create package directory
            this.FS.mkdir(packagePath);
            
            // Download package
            await new Promise((resolve, reject) => {
                this.module.ccall('emscripten_async_wget', null,
                    ['string', 'string', 'number', 'number'],
                    [packageUrl, `${packagePath}/package.zip`, resolve, reject]
                );
            });
            
            // Extract and load certificates (simplified - would need ZIP extraction)
            const certificates = [];
            const files = this.FS.readdir(packagePath);
            
            for (const file of files) {
                if (file.endsWith('.crt') || file.endsWith('.pem')) {
                    const certPath = `${packagePath}/${file}`;
                    const certData = this.FS.readFile(certPath);
                    const certId = `${packageName}_${file.replace(/\.(crt|pem)$/, '')}`;
                    
                    try {
                        await this.loadCertificateFromBuffer(certData, certId, options);
                        certificates.push(certId);
                    } catch (error) {
                        console.warn(`⚠️ Failed to load certificate from package: ${file}`, error);
                    }
                }
            }
            
            console.log(`✅ Loaded ${certificates.length} certificates from package ${packageName}`);
            return certificates;
            
        } catch (error) {
            console.error(`🚨 Failed to load certificate package ${packageName}:`, error);
            throw error;
        }
    }
    
    async verifyCertificateValidity(certPath) {
        try {
            // Load certificate for verification
            const certPtr = this.x509_load_cert_file(certPath, 1);
            if (certPtr === 0) {
                return false;
            }
            
            // Verify certificate
            const result = this.x509_verify_cert(certPtr);
            
            // Clean up
            this.x509_free(certPtr);
            
            return result === 1;
            
        } catch (error) {
            console.error('Certificate validation error:', error);
            return false;
        }
    }
    
    async verifyDataIntegrity(data, expectedHash, algorithm = 'SHA-256') {
        if (!expectedHash) return true;
        
        try {
            const hashBuffer = await crypto.subtle.digest(algorithm, data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            
            const isValid = hashHex.toLowerCase() === expectedHash.toLowerCase();
            
            if (!isValid) {
                console.error('🚨 Data integrity verification FAILED');
                console.error(`Expected: ${expectedHash}`);
                console.error(`Actual:   ${hashHex}`);
            }
            
            return isValid;
            
        } catch (error) {
            console.error('Integrity verification error:', error);
            return false;
        }
    }
    
    loadCertificateFromPath(certPath, certificateId) {
        try {
            const certData = this.FS.readFile(certPath);
            return this.loadCertificateFromBuffer(certData, certificateId);
        } catch (error) {
            console.error(`Failed to load certificate from path ${certPath}:`, error);
            throw error;
        }
    }
    
    getCertificateInfo(certificateId) {
        return this.loadedCertificates.get(certificateId) || null;
    }
    
    listLoadedCertificates() {
        return Array.from(this.loadedCertificates.values()).map(cert => ({
            id: cert.id,
            size: cert.size,
            loadedAt: cert.loadedAt,
            options: cert.options
        }));
    }
    
    getEnabledFeatures() {
        return {
            persistentCache: this.config.persistentCache,
            asyncLoading: this.config.asyncLoading,
            cdnSupport: this.config.cdnSupport,
            encryptClientCerts: this.config.encryptClientCerts,
            verifyCertificateIntegrity: this.config.verifyCertificateIntegrity,
            sessionCache: this.sessionCache.isEnabled(),
            privateKeyManager: true
        };
    }
    
    logEnabledFeatures() {
        const features = this.getEnabledFeatures();
        console.log('🏆 OpenSSL WASM-Native Features:');
        Object.entries(features).forEach(([feature, enabled]) => {
            console.log(`  ${enabled ? '✅' : '❌'} ${feature}`);
        });
    }
    
    cleanup() {
        console.log('🧹 OpenSSL WASM-Native cleanup...');
        
        // Clean up loaded certificates
        this.loadedCertificates.forEach((cert, id) => {
            try {
                if (cert.ptr) this.x509_free(cert.ptr);
                if (cert.path) this.FS.unlink(cert.path);
            } catch (e) {
                console.warn(`Failed to cleanup certificate ${id}:`, e);
            }
        });
        this.loadedCertificates.clear();
        
        // Clean up private keys
        this.privateKeyManager.cleanup();
        
        // Clean up sessions
        this.sessionCache.cleanup();
        
        // Final IDBFS sync
        if (this.config.persistentCache) {
            this.FS.syncfs(false, (err) => {
                if (err) {
                    console.warn('Final IDBFS sync failed:', err);
                } else {
                    console.log('💾 Final state synced to IDBFS');
                }
            });
        }
        
        // OpenSSL cleanup
        if (this.initialized) {
            this.openssl_cleanup();
        }
        
        console.log('✅ OpenSSL WASM-Native cleanup complete');
    }
}

// Secure Private Key Manager
class SecurePrivateKeyManager {
    constructor(FS) {
        this.FS = FS;
        this.activeKeys = new Map();
        this.cleanupHandlers = [];
        
        // Register cleanup on page unload
        if (typeof window !== 'undefined') {
            ['beforeunload', 'pagehide'].forEach(event => {
                window.addEventListener(event, () => this.cleanup());
            });
        }
    }
    
    storePrivateKey(keyId, keyData, passphrase = null) {
        // CRITICAL: Store in MEMFS only - NEVER IDBFS
        const keyPath = `/ssl-temp/private-keys/${keyId}.key`;
        this.FS.writeFile(keyPath, new Uint8Array(keyData));
        
        this.activeKeys.set(keyId, {
            path: keyPath,
            created: Date.now(),
            passphrase: passphrase // Also memory-only
        });
        
        // Auto-cleanup after timeout
        setTimeout(() => this.removePrivateKey(keyId), 30 * 60 * 1000); // 30 min
        
        console.log(`🔐 Private key stored (memory-only): ${keyId}`);
        return keyPath;
    }
    
    getPrivateKeyPath(keyId) {
        const keyInfo = this.activeKeys.get(keyId);
        return keyInfo ? keyInfo.path : null;
    }
    
    removePrivateKey(keyId) {
        const keyInfo = this.activeKeys.get(keyId);
        if (keyInfo) {
            try {
                // Overwrite with random data before deletion
                const keyData = this.FS.readFile(keyInfo.path);
                const randomData = new Uint8Array(keyData.length);
                crypto.getRandomValues(randomData);
                this.FS.writeFile(keyInfo.path, randomData);
                
                // Delete file and memory reference
                this.FS.unlink(keyInfo.path);
                this.activeKeys.delete(keyId);
                
                console.log(`🔒 Private key securely deleted: ${keyId}`);
                
            } catch (e) {
                console.warn(`Failed to securely delete private key ${keyId}:`, e);
            }
        }
    }
    
    cleanup() {
        console.log('🧹 Cleaning up private keys...');
        for (const keyId of this.activeKeys.keys()) {
            this.removePrivateKey(keyId);
        }
    }
}

// Intelligent Certificate Cache
class IntelligentCertificateCache {
    constructor(FS, config) {
        this.FS = FS;
        this.config = config;
        this.memoryCache = new Map(); // L1: Memory cache
        this.persistentEnabled = false; // L2: IDBFS cache
        this.maxSize = config.maxCacheSize || 50;
        this.maxAge = config.maxCacheAge || (7 * 24 * 60 * 60 * 1000); // 1 week
    }
    
    async initialize() {
        this.persistentEnabled = this.config.persistentCache;
        console.log(`📋 Certificate cache initialized (persistent: ${this.persistentEnabled})`);
    }
    
    async get(key) {
        // Check memory cache first
        if (this.memoryCache.has(key)) {
            const cached = this.memoryCache.get(key);
            if (!this.isExpired(cached)) {
                return cached;
            } else {
                this.memoryCache.delete(key);
            }
        }
        
        // Check persistent cache
        if (this.persistentEnabled) {
            const cachePath = `${this.config.directories.cache}/cert-chains/${key}`;
            if (this.FS.analyzePath(cachePath).exists) {
                try {
                    const cachedData = this.FS.readFile(cachePath);
                    const cached = JSON.parse(new TextDecoder().decode(cachedData));
                    
                    if (!this.isExpired(cached)) {
                        // Restore to memory cache
                        this.memoryCache.set(key, cached);
                        return cached;
                    } else {
                        // Remove expired cache
                        this.FS.unlink(cachePath);
                    }
                } catch (e) {
                    console.warn(`Failed to read cached certificate ${key}:`, e);
                }
            }
        }
        
        return null;
    }
    
    async set(key, value) {
        const cached = {
            data: value.data,
            url: value.url,
            loadedAt: Date.now(),
            hash: value.hash
        };
        
        // Store in memory cache
        this.memoryCache.set(key, cached);
        
        // Store in persistent cache
        if (this.persistentEnabled) {
            const cachePath = `${this.config.directories.cache}/cert-chains/${key}`;
            try {
                const cacheData = new TextEncoder().encode(JSON.stringify(cached));
                this.FS.writeFile(cachePath, cacheData);
                
                // Sync to IndexedDB
                this.FS.syncfs(false, (err) => {
                    if (err) console.warn('IDBFS sync failed:', err);
                });
                
            } catch (e) {
                console.warn(`Failed to cache certificate ${key}:`, e);
            }
        }
        
        // Enforce size limits
        await this.enforceSizeLimits();
    }
    
    isExpired(cached) {
        return (Date.now() - cached.loadedAt) > this.maxAge;
    }
    
    async enforceSizeLimits() {
        if (this.memoryCache.size > this.maxSize) {
            // Remove oldest entries
            const entries = Array.from(this.memoryCache.entries());
            entries.sort((a, b) => a[1].loadedAt - b[1].loadedAt);
            
            const toRemove = entries.slice(0, entries.length - this.maxSize);
            toRemove.forEach(([key]) => {
                this.memoryCache.delete(key);
                
                // Also remove from persistent cache
                if (this.persistentEnabled) {
                    const cachePath = `${this.config.directories.cache}/cert-chains/${key}`;
                    try {
                        this.FS.unlink(cachePath);
                    } catch (e) {
                        // File might not exist
                    }
                }
            });
            
            console.log(`🧹 Removed ${toRemove.length} cached certificates (size limit: ${this.maxSize})`);
        }
    }
}

// Secure SSL Session Cache  
class SecureSSLSessionCache {
    constructor(FS, config) {
        this.FS = FS;
        this.config = config;
        this.memoryCache = new Map();
        this.encryptionKey = null;
        this.enabled = false;
    }
    
    async initialize(encryptionKey = null) {
        this.encryptionKey = encryptionKey;
        this.enabled = this.config.persistentCache && !!encryptionKey;
        console.log(`🎫 SSL session cache initialized (enabled: ${this.enabled})`);
    }
    
    isEnabled() {
        return this.enabled;
    }
    
    async storeSession(sessionId, sessionData) {
        // Always store in memory for active use
        this.memoryCache.set(sessionId, {
            data: sessionData,
            timestamp: Date.now()
        });
        
        // Encrypt and store persistent copy
        if (this.enabled && this.encryptionKey) {
            try {
                const encryptedData = await this.encryptSessionData(sessionData);
                const cachePath = `${this.config.directories.cache}/session-tickets/${sessionId}`;
                this.FS.writeFile(cachePath, encryptedData);
                
                // Sync to IndexedDB
                this.FS.syncfs(false, (err) => {
                    if (err) console.warn('Session cache sync failed:', err);
                });
                
            } catch (e) {
                console.warn(`Failed to cache session ${sessionId}:`, e);
            }
        }
    }
    
    async loadSession(sessionId) {
        // Check active memory first
        if (this.memoryCache.has(sessionId)) {
            const cached = this.memoryCache.get(sessionId);
            if (!this.isSessionExpired(cached)) {
                return cached.data;
            } else {
                this.memoryCache.delete(sessionId);
            }
        }
        
        // Try persistent cache
        if (this.enabled && this.encryptionKey) {
            const cachePath = `${this.config.directories.cache}/session-tickets/${sessionId}`;
            
            if (this.FS.analyzePath(cachePath).exists) {
                try {
                    const encryptedData = this.FS.readFile(cachePath);
                    const sessionData = await this.decryptSessionData(encryptedData);
                    
                    // Restore to memory cache
                    this.memoryCache.set(sessionId, {
                        data: sessionData,
                        timestamp: Date.now()
                    });
                    
                    return sessionData;
                    
                } catch (e) {
                    console.warn(`Failed to decrypt session ${sessionId}:`, e);
                    // Remove corrupted cache
                    this.FS.unlink(cachePath);
                }
            }
        }
        
        return null;
    }
    
    async encryptSessionData(sessionData) {
        // Simplified encryption - in production, use proper encryption
        // This is a placeholder implementation
        return new TextEncoder().encode(JSON.stringify({
            encrypted: true,
            data: Array.from(new Uint8Array(sessionData))
        }));
    }
    
    async decryptSessionData(encryptedData) {
        // Simplified decryption - placeholder implementation
        const decoded = JSON.parse(new TextDecoder().decode(encryptedData));
        return new Uint8Array(decoded.data);
    }
    
    isSessionExpired(cached) {
        const sessionTimeout = this.config.sessionTimeout || (30 * 60 * 1000); // 30 minutes
        return (Date.now() - cached.timestamp) > sessionTimeout;
    }
    
    cleanup() {
        this.memoryCache.clear();
    }
}

// Export for use
if (typeof module !== 'undefined' && module.exports) {
    module.exports = OpenSSLWASMNative;
} else if (typeof window !== 'undefined') {
    window.OpenSSLWASMNative = OpenSSLWASMNative;
}