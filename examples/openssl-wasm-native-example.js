// OpenSSL WASM-Native Usage Example
// Copyright 2025 Superstruct Ltd, New Zealand. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License"). You may not use
// this file except in compliance with the License. You can obtain a copy
// in the file LICENSE.txt in the source distribution or at
// https://www.openssl.org/source/license.html
//
// Security-first certificate management with persistent storage

async function demonstrateOpenSSLWASMNative() {
    console.log('🔐 OpenSSL WASM-Native Demo');
    
    try {
        // Load the WASM module
        const OpenSSLModule = await import('../wasm/openssl.js');
        const module = await OpenSSLModule.default();
        
        // Create WASM-native instance
        const openssl = new OpenSSLWASMNative(module);
        
        // Initialize with secure configuration
        const result = await openssl.initialize({
            persistentCache: true,
            encryptClientCerts: true,
            verifyCertificateIntegrity: true,
            trustedCdnSources: ['mozilla.org', 'letsencrypt.org']
        });
        
        if (!result.success) {
            throw new Error(`Initialization failed: ${result.error}`);
        }
        
        console.log('✅ OpenSSL initialized successfully');
        console.log('Features:', result.features);
        
        // Load CA bundle from CDN
        console.log('📦 Loading Mozilla CA bundle...');
        await openssl.loadCABundleFromCDN('mozilla', 'mozilla-ca-bundle');
        
        // Load certificate from URL
        console.log('🌐 Loading Let\'s Encrypt certificate...');
        await openssl.loadCertificateFromUrl(
            'https://letsencrypt.org/certs/isrgrootx1.pem',
            'letsencrypt-root'
        );
        
        // List loaded certificates
        const certificates = openssl.listLoadedCertificates();
        console.log('📋 Loaded certificates:', certificates);
        
        // Demonstrate certificate info
        const certInfo = openssl.getCertificateInfo('letsencrypt-root');
        if (certInfo) {
            console.log('📜 Certificate info:', certInfo);
        }
        
        // Clean up
        openssl.cleanup();
        
        console.log('🏆 Demo completed successfully');
        
    } catch (error) {
        console.error('🚨 Demo failed:', error);
    }
}

// Run demo if this file is executed directly
if (typeof window === 'undefined' && typeof require !== 'undefined') {
    demonstrateOpenSSLWASMNative();
}

export { demonstrateOpenSSLWASMNative };
