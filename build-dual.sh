#!/bin/bash

# OpenSSL WASM Dual Build System
# Builds both SIDE_MODULE (production) and MAIN_MODULE (testing) variants
# Copyright 2025 Superstruct Ltd, New Zealand. All Rights Reserved.

set -euo pipefail

VARIANT="${1:-all}"
LIBRARY_NAME="openssl"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}ℹ️  $1${NC}"; }
log_success() { echo -e "${GREEN}✅ $1${NC}"; }
log_warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }
log_error() { echo -e "${RED}🚨 $1${NC}"; }

print_header() {
    echo
    echo "=========================================="
    echo "🔐 OpenSSL WASM Dual Build System"
    echo "=========================================="
    echo "Build Variant: $VARIANT"
    echo "Library: $LIBRARY_NAME"
    echo "Date: $(date)"
    echo "=========================================="
    echo
}

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check Emscripten
    if ! command -v emcc &> /dev/null; then
        log_error "Emscripten not found. Install with: source /path/to/emsdk/emsdk_env.sh"
        exit 1
    fi

    EMCC_VERSION=$(emcc --version | head -n1 | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+')
    log_info "Emscripten version: $EMCC_VERSION"

    # Check required tools
    for tool in make cmake perl python3; do
        if ! command -v $tool &> /dev/null; then
            log_error "$tool not found. Please install $tool."
            exit 1
        fi
    done

    # Ensure OpenSSL foundation is built
    if [ ! -f "install-foundation/lib/libcrypto.a" ] || [ ! -f "install-foundation/lib/libssl.a" ]; then
        log_warning "Foundation libraries not found. Building foundation first..."
        ./build-wasm-native.sh foundation
    fi

    log_success "Prerequisites check passed"
}

setup_build_dirs() {
    log_info "Setting up build directories..."

    mkdir -p build-dual build-side build-main install/wasm

    log_success "Build directories created"
}

build_side_module() {
    log_info "Building SIDE_MODULE for production..."

    cd build-side

    # Copy WASM-specific source files
    cp ../wasm/openssl-pre-native.js .

    # SIDE_MODULE build - Include OpenSSL but NO Emscripten system libraries
    emcc ../src/wasm_module_simd.c \
        -L../install-foundation/lib \
        -lssl -lcrypto \
        -O3 -flto -fPIC -msimd128 \
        -sSIDE_MODULE=2 \
        -sSTANDALONE_WASM=1 \
        -sEXPORTED_FUNCTIONS='[
            "_openssl_init",
            "_openssl_get_version",
            "_openssl_get_version_number",
            "_openssl_has_simd",
            "_openssl_rand_bytes",
            "_openssl_rand_pseudo_bytes",
            "_openssl_sha256",
            "_openssl_sha1",
            "_openssl_md5",
            "_openssl_hmac_sha256",
            "_openssl_aes_256_cbc_encrypt",
            "_openssl_aes_256_cbc_decrypt",
            "_openssl_rsa_generate_key",
            "_openssl_benchmark_simd",
            "_openssl_get_error",
            "_openssl_get_error_string"
        ]' \
        -I../install-foundation/include \
        -o ../install/wasm/${LIBRARY_NAME}-side.wasm

    cd ..

    log_success "SIDE_MODULE built: $(du -h install/wasm/${LIBRARY_NAME}-side.wasm | cut -f1)"
}

build_main_module() {
    log_info "Building MAIN_MODULE for testing..."

    cd build-main

    # Copy WASM-specific source files
    cp ../src/wasm_module.c .
    cp ../wasm/openssl-pre-native.js .

    # MAIN_MODULE build with standard implementation for testing
    emcc wasm_module.c \
        -L../install-foundation/lib \
        -lssl -lcrypto \
        -O3 -flto \
        -sMODULARIZE=1 \
        -sEXPORT_ES6=1 \
        -sEXPORT_NAME="OpenSSLModule" \
        -sSINGLE_FILE=0 \
        -sEXPORTED_FUNCTIONS='[
            "_openssl_init_crypto",
            "_openssl_init_ssl",
            "_openssl_cleanup",
            "_openssl_get_version",
            "_openssl_get_version_number",
            "_openssl_has_simd",
            "_openssl_rand_bytes",
            "_openssl_rand_pseudo_bytes",
            "_openssl_sha256",
            "_openssl_sha1",
            "_openssl_md5",
            "_openssl_hmac_sha256",
            "_openssl_aes_256_cbc_encrypt",
            "_openssl_aes_256_cbc_decrypt",
            "_openssl_rsa_generate_key",
            "_openssl_get_error",
            "_openssl_get_error_string",
            "_openssl_hash_standard",
            "_openssl_aes_encrypt_standard",
            "_openssl_rsa_verify_standard",
            "_openssl_ec_point_mul_standard",
            "_openssl_benchmark_simd"
        ]' \
        -sEXPORTED_RUNTIME_METHODS='["ccall","cwrap","UTF8ToString","stringToUTF8","lengthBytesUTF8","setValue","getValue","HEAPU8","HEAP32"]' \
        -sALLOW_MEMORY_GROWTH=1 \
        -sINITIAL_MEMORY=67108864 \
        -sMAXIMUM_MEMORY=536870912 \
        -sSTACK_SIZE=5242880 \
        -sENVIRONMENT=web,webview,worker \
        -sNODEJS_CATCH_EXIT=0 \
        -sNODEJS_CATCH_REJECTION=0 \
        --pre-js openssl-pre-native.js \
        -I../install-foundation/include \
        -o ../install/wasm/${LIBRARY_NAME}-main.js

    cd ..

    log_success "MAIN_MODULE built:"
    ls -lah install/wasm/${LIBRARY_NAME}-main.*
}

validate_build() {
    log_info "Validating build outputs..."

    # Check SIDE_MODULE
    if [ "$VARIANT" = "all" ] || [ "$VARIANT" = "side" ]; then
        if [ -f "install/wasm/${LIBRARY_NAME}-side.wasm" ]; then
            SIZE=$(du -h install/wasm/${LIBRARY_NAME}-side.wasm | cut -f1)
            log_success "SIDE_MODULE validated: $SIZE"
        else
            log_error "SIDE_MODULE build failed"
            exit 1
        fi
    fi

    # Check MAIN_MODULE
    if [ "$VARIANT" = "all" ] || [ "$VARIANT" = "main" ]; then
        if [ -f "install/wasm/${LIBRARY_NAME}-main.js" ] && [ -f "install/wasm/${LIBRARY_NAME}-main.wasm" ]; then
            JS_SIZE=$(du -h install/wasm/${LIBRARY_NAME}-main.js | cut -f1)
            WASM_SIZE=$(du -h install/wasm/${LIBRARY_NAME}-main.wasm | cut -f1)
            log_success "MAIN_MODULE validated: JS=$JS_SIZE, WASM=$WASM_SIZE"
        else
            log_error "MAIN_MODULE build failed"
            exit 1
        fi
    fi
}

print_summary() {
    echo
    echo "=========================================="
    echo "🏆 OpenSSL WASM Build Complete"
    echo "=========================================="
    echo

    if [ "$VARIANT" = "all" ] || [ "$VARIANT" = "side" ]; then
        echo "✅ SIDE_MODULE (Production):"
        echo "   📦 File: install/wasm/${LIBRARY_NAME}-side.wasm"
        echo "   💾 Size: $(du -h install/wasm/${LIBRARY_NAME}-side.wasm | cut -f1)"
        echo "   🎯 Usage: Dynamic loading via dlopen()"
        echo "   🌐 CDN: https://wasm.discere.cloud/openssl/latest/side/"
        echo
    fi

    if [ "$VARIANT" = "all" ] || [ "$VARIANT" = "main" ]; then
        echo "✅ MAIN_MODULE (Testing/NPM):"
        echo "   📦 Files: install/wasm/${LIBRARY_NAME}-main.js/.wasm"
        echo "   💾 Size: $(du -h install/wasm/${LIBRARY_NAME}-main.* | awk '{sum+=$1} END {print sum}')KB total"
        echo "   🎯 Usage: Direct ES6 import for testing"
        echo "   📚 NPM: @discere-os/openssl.wasm"
        echo
    fi

    echo "🚀 Next steps:"
    echo "   deno task demo    # Test the build"
    echo "   deno task test    # Run test suite"
    echo "   deno task bench   # Performance benchmarks"
    echo
    echo "=========================================="
}

# Main execution
main() {
    print_header
    check_prerequisites
    setup_build_dirs

    case "$VARIANT" in
        "side")
            build_side_module
            ;;
        "main")
            build_main_module
            ;;
        "all")
            build_side_module
            build_main_module
            ;;
        *)
            log_error "Invalid variant: $VARIANT. Use: side, main, or all"
            exit 1
            ;;
    esac

    validate_build
    print_summary
}

main "$@"