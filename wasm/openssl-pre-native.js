// OpenSSL WASM-Native Pre-initialization
// 
// WASM Integration Copyright (c) 2025 Superstruct Ltd, New Zealand
// Licensed under the same license as the underlying OpenSSL project (Apache License 2.0)
//
// You can obtain a copy of the License in the file LICENSE.txt in the source 
// distribution or at https://www.openssl.org/source/license.html
//
// Enhanced with IDBFS persistent storage, async loading, and security-first design
// Advanced WASM-native pre-initialization for OpenSSL

// WASM-native configuration for OpenSSL
var OpenSSL_WASM_NATIVE_CONFIG = {
    // File system configuration
    persistentCache: true,          // Enable IDBFS persistent storage
    asyncLoading: true,             // Enable async certificate loading
    cdnSupport: true,               // Enable loading from trusted CDNs
    
    // Security configuration  
    encryptClientCerts: true,       // Encrypt client certificates in storage
    persistentPrivateKeys: false,   // NEVER enable - security critical
    verifyCertificateIntegrity: true, // Always verify certificate integrity
    
    // Performance configuration
    maxCacheSize: 50,               // Maximum cached certificates
    maxCacheAge: 7 * 24 * 60 * 60 * 1000, // 1 week cache lifetime
    sessionTimeout: 30 * 60 * 1000, // 30 minute session timeout
    
    // Trusted sources for certificate loading
    trustedCdnSources: [
        'mozilla.org',              // Mozilla CA bundle
        'letsencrypt.org',         // Let's Encrypt certificates
        'curl.se',                 // curl CA bundle
        'chromium.org'             // Chromium root store
    ],
    
    // Directory structure
    directories: {
        system: '/ssl-system',      // System certificates (preloaded)
        cache: '/ssl-cache',        // IDBFS persistent cache
        temp: '/ssl-temp',          // MEMFS temporary (private keys)
        packages: '/ssl-packages',  // Certificate packages
        remote: '/ssl-remote'       // Async-loaded certificates
    }
};

// Pre-run initialization for WASM-native features
Module['preRun'] = Module['preRun'] || [];
Module['preRun'].push(function() {
    console.log('🔐 OpenSSL WASM-Native initializing...');
    
    try {
        // Create directory structure
        var dirs = OpenSSL_WASM_NATIVE_CONFIG.directories;
        Object.values(dirs).forEach(function(dir) {
            try {
                FS.mkdir(dir);
                console.log('📁 Created directory:', dir);
            } catch(e) {
                // Directory might already exist
            }
        });
        
        // Initialize subdirectories
        [
            dirs.cache + '/ca-bundles',
            dirs.cache + '/cert-chains', 
            dirs.cache + '/ocsp-responses',
            dirs.cache + '/crl-cache',
            dirs.cache + '/session-tickets',
            dirs.temp + '/private-keys',
            dirs.temp + '/active-sessions',
            dirs.temp + '/validation-temp',
            dirs.packages + '/enterprise-cas',
            dirs.packages + '/gov-roots',
            dirs.packages + '/custom-chains',
            dirs.remote + '/cdn-certs',
            dirs.remote + '/ocsp-live',
            dirs.remote + '/crl-live'
        ].forEach(function(dir) {
            try {
                FS.mkdir(dir);
            } catch(e) {
                // Subdirectory creation may fail, that's ok
            }
        });
        
        console.log('✅ OpenSSL WASM-Native directory structure created');
        
    } catch(e) {
        console.warn('⚠️ OpenSSL WASM-Native directory creation failed:', e);
    }
});

// Post-run initialization for persistent storage
Module['postRun'] = Module['postRun'] || [];
Module['postRun'].push(function() {
    console.log('🚀 OpenSSL WASM-Native post-initialization...');
    
    // Initialize IDBFS if available and enabled
    if (OpenSSL_WASM_NATIVE_CONFIG.persistentCache && 
        typeof indexedDB !== 'undefined') {
        try {
            var cacheDir = OpenSSL_WASM_NATIVE_CONFIG.directories.cache;
            FS.mount(FS.filesystems.IDBFS, {}, cacheDir);
            console.log('💾 IDBFS mounted at:', cacheDir);
            
            // Synchronize with IndexedDB
            FS.syncfs(true, function(err) {
                if (err) {
                    console.warn('⚠️ IDBFS sync failed:', err);
                } else {
                    console.log('✅ IDBFS synchronized with IndexedDB');
                }
            });
            
        } catch(e) {
            console.warn('⚠️ IDBFS initialization failed:', e);
            console.log('📝 Falling back to MEMFS for certificate caching');
            OpenSSL_WASM_NATIVE_CONFIG.persistentCache = false;
        }
    } else {
        console.log('📝 IDBFS disabled, using MEMFS for all operations');
        OpenSSL_WASM_NATIVE_CONFIG.persistentCache = false;
    }
    
    // Register cleanup handlers for security
    if (typeof window !== 'undefined') {
        ['beforeunload', 'pagehide'].forEach(function(event) {
            window.addEventListener(event, function() {
                console.log('🧹 OpenSSL cleanup on page unload...');
                
                // Clean private keys from memory
                try {
                    var privateKeysDir = OpenSSL_WASM_NATIVE_CONFIG.directories.temp + '/private-keys';
                    var files = FS.readdir(privateKeysDir);
                    
                    files.forEach(function(file) {
                        if (file !== '.' && file !== '..') {
                            var keyPath = privateKeysDir + '/' + file;
                            try {
                                // Overwrite with random data before deletion
                                var keyData = FS.readFile(keyPath);
                                var randomData = new Uint8Array(keyData.length);
                                crypto.getRandomValues(randomData);
                                FS.writeFile(keyPath, randomData);
                                FS.unlink(keyPath);
                                console.log('🔒 Securely deleted private key:', file);
                            } catch(e) {
                                console.warn('⚠️ Failed to clean private key:', file, e);
                            }
                        }
                    });
                    
                } catch(e) {
                    console.warn('⚠️ Private key cleanup failed:', e);
                }
                
                // Sync final state to IDBFS
                if (OpenSSL_WASM_NATIVE_CONFIG.persistentCache) {
                    try {
                        FS.syncfs(false, function(err) {
                            if (err) {
                                console.warn('⚠️ Final IDBFS sync failed:', err);
                            } else {
                                console.log('💾 Final state synced to IDBFS');
                            }
                        });
                    } catch(e) {
                        console.warn('⚠️ Final sync error:', e);
                    }
                }
            });
        });
    }
    
    console.log('🏆 OpenSSL WASM-Native initialization complete');
    console.log('Features enabled:');
    console.log('  📁 Persistent storage:', OpenSSL_WASM_NATIVE_CONFIG.persistentCache);
    console.log('  🌐 Async loading:', OpenSSL_WASM_NATIVE_CONFIG.asyncLoading);
    console.log('  🔐 Certificate verification:', OpenSSL_WASM_NATIVE_CONFIG.verifyCertificateIntegrity);
    console.log('  🚫 Private key persistence:', OpenSSL_WASM_NATIVE_CONFIG.persistentPrivateKeys);
});

// Make configuration available globally
if (typeof window !== 'undefined') {
    window.OpenSSL_WASM_NATIVE_CONFIG = OpenSSL_WASM_NATIVE_CONFIG;
}