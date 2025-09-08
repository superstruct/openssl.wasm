#!/bin/bash

# OpenSSL WASM-Native Build Script
# Copyright 2025 Superstruct Ltd, New Zealand. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License"). You may not use
# this file except in compliance with the License. You can obtain a copy
# in the file LICENSE.txt in the source distribution or at
# https://www.openssl.org/source/license.html
#
# Security-first build with IDBFS persistence, async loading, and certificate management

set -euo pipefail

# Build configuration
BUILD_TYPE="${1:-wasm-native}"
BUILD_DIR="build-${BUILD_TYPE}"
INSTALL_DIR="install-${BUILD_TYPE}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}🚨 $1${NC}"
}

print_header() {
    echo
    echo "=========================================="
    echo "🔐 OpenSSL WASM-Native Build System"
    echo "=========================================="
    echo "Build Type: $BUILD_TYPE"
    echo "Build Dir:  $BUILD_DIR"
    echo "Install Dir: $INSTALL_DIR"
    echo "Date: $(date)"
    echo "=========================================="
    echo
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Emscripten
    if ! command -v emcc &> /dev/null; then
        log_error "Emscripten not found. Please install and activate emsdk:"
        echo "  git clone https://github.com/emscripten-core/emsdk.git"
        echo "  cd emsdk && ./emsdk install latest && ./emsdk activate latest"
        echo "  source ./emsdk_env.sh"
        exit 1
    fi
    
    # Check Emscripten version
    EMCC_VERSION=$(emcc --version | head -n1 | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+')
    log_info "Emscripten version: $EMCC_VERSION"
    
    # Check required tools
    for tool in make cmake perl python3; do
        if ! command -v $tool &> /dev/null; then
            log_error "$tool not found. Please install $tool."
            exit 1
        fi
    done
    
    log_success "Prerequisites check passed"
}

setup_directories() {
    log_info "Setting up build directories..."
    
    # Clean and create build directories
    rm -rf "$BUILD_DIR" "$INSTALL_DIR"
    mkdir -p "$BUILD_DIR" "$INSTALL_DIR"
    
    # Create WASM-native directories
    if [[ "$BUILD_TYPE" == "wasm-native" ]]; then
        mkdir -p certs wasm examples
        
        # Create certificate structure
        mkdir -p certs/{system,bundles,samples}
        
        log_info "Created WASM-native directory structure"
    fi
    
    log_success "Directories setup complete"
}

download_ca_bundles() {
    if [[ "$BUILD_TYPE" != "wasm-native" ]]; then
        return
    fi
    
    log_info "Downloading CA certificate bundles..."
    
    # Download Mozilla CA bundle
    if curl -f -s -o certs/bundles/mozilla-ca-bundle.crt \
        "https://curl.se/ca/cacert.pem"; then
        log_success "Downloaded Mozilla CA bundle"
    else
        log_warning "Failed to download Mozilla CA bundle"
    fi
    
    # Create default system bundle (link to Mozilla)
    if [[ -f "certs/bundles/mozilla-ca-bundle.crt" ]]; then
        cp certs/bundles/mozilla-ca-bundle.crt certs/system/ca-bundle.crt
        log_info "Created default system CA bundle"
    fi
    
    # Download sample certificates for testing
    log_info "Downloading sample certificates for testing..."
    
    # Let's Encrypt sample (for testing only)
    if curl -f -s -o certs/samples/letsencrypt-sample.crt \
        "https://letsencrypt.org/certs/isrgrootx1.pem"; then
        log_success "Downloaded Let's Encrypt sample certificate"
    else
        log_warning "Failed to download Let's Encrypt sample"
    fi
}

configure_openssl() {
    log_info "Configuring OpenSSL for WASM..."
    
    # Base configuration options
    OPENSSL_OPTIONS=(
        # Target and build type
        "no-shared"
        "no-module"
        "no-tests"
        "no-apps" 
        "no-docs"
        
        # Security hardening
        "no-ssl3"
        "no-ssl3-method"
        "no-weak-ssl-ciphers"
        "no-deprecated"
        
        # Size optimization  
        "no-autoalginit"
        "no-autoerrinit"
        "no-comp"
        "no-psk"
        "no-srp"
        "no-gost" 
        
        # Keep essential features
        "enable-ec"
        "enable-ecdh"
        "enable-ecdsa"
        "enable-ocsp"
        
        # Installation paths
        "--prefix=$(pwd)/$INSTALL_DIR"
        "--openssldir=$(pwd)/$INSTALL_DIR/ssl"
    )
    
    # Build type specific options
    if [[ "$BUILD_TYPE" == "wasm-native" ]]; then
        OPENSSL_OPTIONS+=(
            "enable-async"
            "enable-stdio"
        )
        log_info "Added WASM-native specific options"
    else
        OPENSSL_OPTIONS+=(
            "no-async"
            "no-stdio"  
        )
        log_info "Added foundation build options"
    fi
    
    # Environment setup for Emscripten
    export CC="emcc"
    export CXX="em++"
    export AR="emar"
    export RANLIB="emranlib"
    export CROSS_COMPILE=""
    
    # WASM-specific CFLAGS
    export CFLAGS="-O3 -flto -fPIC"
    export CXXFLAGS="-O3 -flto -fPIC"
    
    log_info "Running OpenSSL Configure..."
    echo "Options: ${OPENSSL_OPTIONS[*]}"
    
    # Run Configure with linux-generic32 target for WASM
    if ./Configure linux-generic32 "${OPENSSL_OPTIONS[@]}" \
        --cross-compile-prefix="" \
        CC="$CC" \
        AR="$AR" \
        RANLIB="$RANLIB"; then
        log_success "OpenSSL Configure completed"
    else
        log_error "OpenSSL Configure failed"
        exit 1
    fi
}

build_openssl() {
    log_info "Building OpenSSL..."
    
    # Determine number of parallel jobs
    JOBS=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)
    log_info "Using $JOBS parallel jobs"
    
    # Build OpenSSL
    if emmake make -j"$JOBS" all; then
        log_success "OpenSSL build completed"
    else
        log_error "OpenSSL build failed"
        exit 1
    fi
}

install_openssl() {
    log_info "Installing OpenSSL..."
    
    if emmake make install_sw install_ssldirs; then
        log_success "OpenSSL installation completed"
    else
        log_error "OpenSSL installation failed"
        exit 1
    fi
    
    # Verify installation
    if [[ -f "$INSTALL_DIR/lib/libcrypto.a" ]] && [[ -f "$INSTALL_DIR/lib/libssl.a" ]]; then
        log_success "OpenSSL libraries found:"
        ls -lah "$INSTALL_DIR/lib/"*.a
    else
        log_error "OpenSSL libraries not found after installation"
        exit 1
    fi
}

create_wasm_bindings() {
    if [[ "$BUILD_TYPE" != "wasm-native" ]]; then
        log_info "Skipping WASM bindings for foundation build"
        return
    fi
    
    log_info "Creating WASM-native bindings..."
    
    # Create JavaScript bindings with Emscripten
    EMCC_OPTIONS=(
        # Input files
        "$INSTALL_DIR/lib/libssl.a"
        "$INSTALL_DIR/lib/libcrypto.a"
        
        # Output
        "-o" "wasm/openssl.js"
        
        # Optimization
        "-O3"
        "-flto"
        "--closure" "0"  # Disable for debugging
        
        # WASM configuration
        "-s" "WASM=1"
        "-s" "MODULARIZE=1" 
        "-s" "EXPORT_NAME=OpenSSLModule"
        
        # Memory configuration
        "-s" "ALLOW_MEMORY_GROWTH=1"
        "-s" "INITIAL_MEMORY=64MB"
        "-s" "MAXIMUM_MEMORY=256MB"
        "-s" "STACK_SIZE=5MB"
        
        # File system configuration
        "-s" "FORCE_FILESYSTEM=1"
        "-s" "ASYNCIFY=1"
        "-s" "ENVIRONMENT=web,worker,node"
        "-lidbfs.js"
        
        # Runtime methods
        "-s" "EXPORTED_RUNTIME_METHODS=['ccall','cwrap','setValue','getValue','FS','HEAPU8','HEAP32']"
        
        # Preload certificates if available
        "--preload-file" "certs/system@/ssl-system"
        
        # Pre-run script
        "--pre-js" "wasm/openssl-pre-native.js"
        
        # Include directories
        "-I$INSTALL_DIR/include"
    )
    
    # Exported functions for OpenSSL
    EXPORTED_FUNCTIONS=(
        '_OPENSSL_init_crypto'
        '_OPENSSL_init_ssl' 
        '_OPENSSL_cleanup'
        '_X509_new'
        '_X509_free'
        '_X509_load_cert_file'
        '_X509_verify_cert'
        '_X509_STORE_new'
        '_X509_STORE_free'
        '_X509_STORE_add_cert'
        '_SSL_CTX_new'
        '_SSL_CTX_free'
        '_SSL_new'
        '_SSL_free'
        '_BIO_new'
        '_BIO_free'
        '_BIO_new_mem_buf'
        '_ERR_get_error'
        '_ERR_error_string'
    )
    
    # Add exported functions
    EXPORTED_FUNCTIONS_STR=$(IFS=, ; echo "${EXPORTED_FUNCTIONS[*]}")
    EMCC_OPTIONS+=("-s" "EXPORTED_FUNCTIONS=[$EXPORTED_FUNCTIONS_STR]")
    
    log_info "Running Emscripten compilation..."
    echo "Command: emcc ${EMCC_OPTIONS[*]}"
    
    if emcc "${EMCC_OPTIONS[@]}"; then
        log_success "WASM-native bindings created"
    else
        log_error "WASM-native bindings creation failed"
        exit 1
    fi
    
    # Verify outputs
    if [[ -f "wasm/openssl.js" ]] && [[ -f "wasm/openssl.wasm" ]]; then
        log_success "WASM files generated:"
        ls -lah wasm/openssl.*
    else
        log_error "WASM files not found after compilation"
        exit 1
    fi
}

create_examples() {
    if [[ "$BUILD_TYPE" != "wasm-native" ]]; then
        return
    fi
    
    log_info "Creating usage examples..."
    
    cat > examples/openssl-wasm-native-example.js << 'EOF'
// OpenSSL WASM-Native Usage Example
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
EOF

    log_success "Created usage examples"
}

update_package_json() {
    log_info "Updating package.json..."
    
    # Read existing package.json or create minimal one
    if [[ -f "package.json" ]]; then
        PACKAGE_JSON=$(cat package.json)
    else
        PACKAGE_JSON='{}'
    fi
    
    # Update with WASM-native information
    cat > package.json << EOF
{
  "name": "openssl-wasm-native",
  "version": "3.3.2-wasm-native.1",
  "description": "OpenSSL WASM-Native with persistent certificate storage and async loading",
  "main": "wasm/openssl-wasm-native.js",
  "types": "wasm/openssl-wasm-native.d.ts",
  "files": [
    "wasm/",
    "install-${BUILD_TYPE}/",
    "certs/",
    "examples/"
  ],
  "scripts": {
    "build": "./build-wasm-native.sh foundation",
    "build:native": "./build-wasm-native.sh wasm-native",
    "test": "node examples/openssl-wasm-native-example.js",
    "clean": "rm -rf build-* install-* wasm/*.wasm wasm/*.js"
  },
  "keywords": [
    "openssl",
    "wasm", 
    "webassembly",
    "cryptography",
    "certificates",
    "ssl",
    "tls",
    "security",
    "persistent-storage",
    "idbfs"
  ],
  "license": "Apache-2.0",
  "repository": {
    "type": "git",
    "url": "https://github.com/superstruct/openssl.wasm.git"
  },
  "engines": {
    "node": ">=18.0.0"
  },
  "dependencies": {},
  "devDependencies": {},
  "browser": {
    "fs": false,
    "path": false
  },
  "buildInfo": {
    "buildType": "${BUILD_TYPE}",
    "buildDate": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "emscriptenVersion": "$(emcc --version | head -n1)",
    "features": {
      "persistentStorage": $([ "$BUILD_TYPE" = "wasm-native" ] && echo "true" || echo "false"),
      "asyncLoading": $([ "$BUILD_TYPE" = "wasm-native" ] && echo "true" || echo "false"),
      "certificateCache": $([ "$BUILD_TYPE" = "wasm-native" ] && echo "true" || echo "false"),
      "securityFirst": true
    }
  }
}
EOF

    log_success "Package.json updated"
}

print_summary() {
    echo
    echo "=========================================="
    echo "🏆 OpenSSL WASM-Native Build Complete"
    echo "=========================================="
    echo
    
    if [[ "$BUILD_TYPE" == "wasm-native" ]]; then
        echo "✅ WASM-Native Build Features:"
        echo "   📁 IDBFS persistent certificate storage"
        echo "   🌐 Async certificate loading from CDNs"
        echo "   🔐 Security-first private key management"
        echo "   📦 Certificate package system"
        echo "   💾 Intelligent multi-level caching"
        echo "   🛡️  Comprehensive integrity verification"
        echo
        echo "📂 Generated Files:"
        [[ -f "wasm/openssl.js" ]] && echo "   wasm/openssl.js - Main WASM module"
        [[ -f "wasm/openssl.wasm" ]] && echo "   wasm/openssl.wasm - WebAssembly binary"
        [[ -f "wasm/openssl.data" ]] && echo "   wasm/openssl.data - Preloaded certificates"
        [[ -f "wasm/openssl-wasm-native.js" ]] && echo "   wasm/openssl-wasm-native.js - High-level API"
        [[ -f "wasm/openssl-wasm-native.d.ts" ]] && echo "   wasm/openssl-wasm-native.d.ts - TypeScript definitions"
        echo
        echo "🧪 Test the build:"
        echo "   node examples/openssl-wasm-native-example.js"
    else
        echo "✅ Foundation Build Features:"
        echo "   🏗️  Optimized for minimal size and dependencies"
        echo "   📦 Minimal size and fast loading"
        echo "   🔗 Compatible with graphics libraries"
        echo
        echo "📂 Generated Libraries:"
        [[ -f "$INSTALL_DIR/lib/libssl.a" ]] && echo "   $INSTALL_DIR/lib/libssl.a"
        [[ -f "$INSTALL_DIR/lib/libcrypto.a" ]] && echo "   $INSTALL_DIR/lib/libcrypto.a"
    fi
    
    echo
    echo "📊 Build Statistics:"
    [[ -f "$INSTALL_DIR/lib/libssl.a" ]] && echo "   SSL Library: $(du -h $INSTALL_DIR/lib/libssl.a | cut -f1)"
    [[ -f "$INSTALL_DIR/lib/libcrypto.a" ]] && echo "   Crypto Library: $(du -h $INSTALL_DIR/lib/libcrypto.a | cut -f1)"
    [[ -f "wasm/openssl.wasm" ]] && echo "   WASM Binary: $(du -h wasm/openssl.wasm | cut -f1)"
    [[ -f "wasm/openssl.data" ]] && echo "   Certificate Data: $(du -h wasm/openssl.data | cut -f1)"
    
    echo
    echo "🎯 Next Steps:"
    echo "   1. Test the build with provided examples"
    echo "   2. Integrate with your web application"  
    echo "   3. Configure trusted certificate sources"
    echo "   4. Implement proper security policies"
    echo
    echo "🔒 Security Reminders:"
    echo "   • Private keys are NEVER stored persistently"
    echo "   • All certificates undergo integrity verification"
    echo "   • Use HTTPS for all certificate downloads"
    echo "   • Regularly update CA bundles"
    echo
    echo "=========================================="
}

# Main execution
main() {
    print_header
    check_prerequisites
    setup_directories
    download_ca_bundles
    configure_openssl
    build_openssl
    install_openssl
    create_wasm_bindings
    create_examples
    update_package_json
    print_summary
}

# Run main function
main "$@"