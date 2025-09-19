#!/usr/bin/env -S deno run --allow-read --allow-write --allow-net

/**
 * OpenSSL WASM Demo - Comprehensive Cryptographic Operations
 *
 * This demo showcases all major features of OpenSSL WASM including:
 * - Hash functions (SHA256, SHA512, MD5) with SIMD optimization
 * - AES encryption/decryption with GCM and CBC modes
 * - RSA signature verification
 * - Elliptic curve operations
 * - Performance benchmarking
 *
 * Copyright 2025 Superstruct Ltd, New Zealand
 * Licensed under Apache-2.0
 */

import OpenSSL from './src/lib/index.ts';
import { OpenSSLConfig } from './src/lib/types.ts';

// Demo configuration
const DEMO_DATA_SIZES = [1024, 8192, 65536, 1048576]; // 1KB, 8KB, 64KB, 1MB
const BENCHMARK_ITERATIONS = 100;

async function runComprehensiveDemo() {
    console.log('🔐 OpenSSL WASM - Comprehensive Cryptographic Demo');
    console.log('================================================\n');

    const openssl = new OpenSSL();

    try {
        // Initialize OpenSSL with verbose logging
        console.log('📦 Initializing OpenSSL WASM...');
        const config: OpenSSLConfig = {
            verbose: true,
            maxMemory: 64 * 1024 * 1024, // 64MB
            enableThreading: false
        };

        await openssl.initialize(config);

        const stats = openssl.getPerformanceStats();
        console.log('✅ OpenSSL initialized successfully');
        console.log(`   Version: ${stats.version}`);
        console.log(`   SIMD Support: ${stats.simdSupported ? '✅ Enabled' : '❌ Disabled'}`);
        console.log(`   Features: ${Object.entries(stats.features).filter(([, enabled]) => enabled).map(([name]) => name).join(', ')}\n`);

        // Demo 1: Hash Functions
        await demoHashFunctions(openssl);

        // Demo 2: AES Encryption
        await demoAESEncryption(openssl);

        // Demo 3: RSA Operations
        await demoRSAOperations(openssl);

        // Demo 4: Elliptic Curve Operations
        await demoEllipticCurveOperations(openssl);

        // Demo 5: Performance Benchmarks
        await demoPerformanceBenchmarks(openssl);

        console.log('🏆 All demos completed successfully!');

    } catch (error) {
        console.error('🚨 Demo failed:', error);
        throw error;
    } finally {
        openssl.cleanup();
        console.log('🧹 OpenSSL cleanup completed');
    }
}

async function demoHashFunctions(openssl: OpenSSL) {
    console.log('1️⃣  Hash Functions Demo');
    console.log('=======================');

    const testData = new TextEncoder().encode('Hello, OpenSSL WASM! This is a test message for hashing.');
    console.log(`📝 Test data: "${new TextDecoder().decode(testData)}" (${testData.length} bytes)`);

    // Test different hash algorithms
    const algorithms: Array<'SHA256' | 'SHA512' | 'MD5'> = ['SHA256', 'SHA512', 'MD5'];

    for (const algorithm of algorithms) {
        const result = openssl.hash(testData, algorithm);
        console.log(`   ${algorithm}: ${result.hexHash} (SIMD: ${result.simdUsed ? '✅' : '❌'})`);
    }

    // Performance test with larger data
    const largeData = new Uint8Array(64 * 1024).fill(42); // 64KB of data
    const start = performance.now();
    const result = openssl.hash(largeData, 'SHA256');
    const elapsed = performance.now() - start;
    const throughput = (largeData.length / elapsed * 1000) / (1024 * 1024); // MB/s

    console.log(`   ⚡ SHA256 64KB performance: ${elapsed.toFixed(2)}ms (${throughput.toFixed(1)} MB/s)\n`);
}

async function demoAESEncryption(openssl: OpenSSL) {
    console.log('2️⃣  AES Encryption Demo');
    console.log('=======================');

    const plaintext = new TextEncoder().encode('This is a confidential message that needs to be encrypted using AES-256!');
    const key = crypto.getRandomValues(new Uint8Array(32)); // 256-bit key

    console.log(`📝 Plaintext: "${new TextDecoder().decode(plaintext)}" (${plaintext.length} bytes)`);
    console.log(`🔑 Key: ${Array.from(key.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join('')}... (256-bit)`);

    // Test different AES modes
    const modes: Array<'GCM' | 'CBC'> = ['GCM', 'CBC'];

    for (const mode of modes) {
        try {
            const encrypted = openssl.aesEncrypt(plaintext, key, mode);
            console.log(`   ${mode}: ${encrypted.data.length} bytes encrypted (SIMD: ${encrypted.simdUsed ? '✅' : '❌'})`);
            console.log(`      Hex: ${Array.from(encrypted.data.slice(0, 16)).map(b => b.toString(16).padStart(2, '0')).join('')}...`);
        } catch (error) {
            console.log(`   ${mode}: ❌ Error - ${error}`);
        }
    }

    // Performance test
    const perfData = new Uint8Array(1024 * 1024).fill(65); // 1MB of 'A's
    const start = performance.now();
    const encrypted = openssl.aesEncrypt(perfData, key, 'GCM');
    const elapsed = performance.now() - start;
    const throughput = (perfData.length / elapsed * 1000) / (1024 * 1024);

    console.log(`   ⚡ AES-256-GCM 1MB performance: ${elapsed.toFixed(2)}ms (${throughput.toFixed(1)} MB/s)\n`);
}

async function demoRSAOperations(openssl: OpenSSL) {
    console.log('3️⃣  RSA Operations Demo');
    console.log('=======================');

    // For the demo, we'll use mock keys since RSA key generation is complex
    const testData = new TextEncoder().encode('Message to be verified with RSA signature');
    const mockSignature = crypto.getRandomValues(new Uint8Array(256)); // Mock 2048-bit signature
    const mockPublicKey = crypto.getRandomValues(new Uint8Array(294)); // Mock DER-encoded public key

    console.log(`📝 Data to verify: "${new TextDecoder().decode(testData)}" (${testData.length} bytes)`);
    console.log(`🔏 Signature: ${Array.from(mockSignature.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join('')}... (${mockSignature.length} bytes)`);

    try {
        const result = openssl.rsaVerify(testData, mockSignature, mockPublicKey);
        console.log(`   Verification: ${result.valid ? '✅ Valid' : '❌ Invalid'} (SIMD: ${result.simdUsed ? '✅' : '❌'})`);
        if (!result.valid && result.error) {
            console.log(`   Error: ${result.error}`);
        }
    } catch (error) {
        console.log(`   RSA Verify: ❌ Error - ${error}`);
    }

    console.log('   Note: Using mock keys for demo - real verification would require valid RSA key pair\n');
}

async function demoEllipticCurveOperations(openssl: OpenSSL) {
    console.log('4️⃣  Elliptic Curve Operations Demo');
    console.log('===================================');

    // Mock P-256 point and scalar for demonstration
    const mockPoint = new Uint8Array(65); // Uncompressed P-256 point
    mockPoint[0] = 0x04; // Uncompressed point indicator
    crypto.getRandomValues(mockPoint.subarray(1)); // Random coordinates

    const mockScalar = crypto.getRandomValues(new Uint8Array(32)); // 256-bit scalar

    console.log(`📐 Point: ${Array.from(mockPoint.slice(0, 9)).map(b => b.toString(16).padStart(2, '0')).join('')}... (65 bytes)`);
    console.log(`🔢 Scalar: ${Array.from(mockScalar.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join('')}... (32 bytes)`);

    try {
        const start = performance.now();
        const result = openssl.ecPointMultiply(mockPoint, mockScalar);
        const elapsed = performance.now() - start;

        console.log(`   Result: ${Array.from(result.slice(0, 9)).map(b => b.toString(16).padStart(2, '0')).join('')}... (65 bytes)`);
        console.log(`   ⚡ Point multiplication: ${elapsed.toFixed(2)}ms`);
    } catch (error) {
        console.log(`   EC Point Multiply: ❌ Error - ${error}`);
        console.log('   Note: Using mock data for demo - real operations require valid curve points');
    }

    console.log();
}

async function demoPerformanceBenchmarks(openssl: OpenSSL) {
    console.log('5️⃣  Performance Benchmarks');
    console.log('===========================');

    const simdStatus = openssl.hasSIMD();
    console.log(`🚀 SIMD Status: ${simdStatus ? 'Enabled' : 'Disabled'}\n`);

    // Benchmark hash functions across different data sizes
    console.log('📊 Hash Function Performance:');
    for (const size of [1024, 8192, 65536]) {
        const data = crypto.getRandomValues(new Uint8Array(size));
        const iterations = size <= 8192 ? 1000 : 100;

        const start = performance.now();
        for (let i = 0; i < iterations; i++) {
            openssl.hash(data, 'SHA256');
        }
        const elapsed = performance.now() - start;

        const avgTime = elapsed / iterations;
        const throughput = (size / avgTime * 1000) / (1024 * 1024);

        console.log(`   ${(size/1024).toFixed(0).padStart(2)}KB: ${avgTime.toFixed(3)}ms avg, ${throughput.toFixed(1)} MB/s`);
    }

    // Memory usage stats
    const memStats = {
        used: (performance as any).memory?.usedJSHeapSize || 0,
        total: (performance as any).memory?.totalJSHeapSize || 0,
        limit: (performance as any).memory?.jsHeapSizeLimit || 0
    };

    if (memStats.total > 0) {
        console.log(`\n💾 Memory Usage:`);
        console.log(`   Used: ${(memStats.used / 1024 / 1024).toFixed(2)} MB`);
        console.log(`   Total: ${(memStats.total / 1024 / 1024).toFixed(2)} MB`);
        console.log(`   Limit: ${(memStats.limit / 1024 / 1024).toFixed(2)} MB`);
    }

    console.log();
}

// Run the demo if this file is executed directly
if (import.meta.main) {
    try {
        await runComprehensiveDemo();
        console.log('\n🎉 Demo completed successfully!');
    } catch (error) {
        console.error('\n💥 Demo failed:', error);
        Deno.exit(1);
    }
}

export { runComprehensiveDemo };