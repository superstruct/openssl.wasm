#!/usr/bin/env -S deno run --allow-read --allow-write

/**
 * OpenSSL WASM Performance Benchmarks
 *
 * Comprehensive benchmarking suite for measuring cryptographic
 * operation performance with SIMD optimization analysis.
 *
 * Copyright 2025 Superstruct Ltd, New Zealand
 * Licensed under Apache-2.0
 */

import OpenSSL from "../src/lib/index.ts";

// Benchmark configuration
const WARMUP_ITERATIONS = 10;
const BENCHMARK_ITERATIONS = 100;
const DATA_SIZES = [1024, 8192, 65536, 1048576]; // 1KB, 8KB, 64KB, 1MB
const SMALL_ITERATIONS = 1000;
const LARGE_ITERATIONS = 10;

let openssl: OpenSSL | null = null;

// Setup and teardown
async function setupOpenSSL(): Promise<void> {
    openssl = new OpenSSL();
    await openssl.initialize({ verbose: false });
}

function cleanupOpenSSL(): void {
    openssl?.cleanup();
    openssl = null;
}

// Benchmark helper
async function runBenchmark<T>(
    name: string,
    operation: () => T,
    iterations: number = BENCHMARK_ITERATIONS
): Promise<{ avgTime: number; throughputMBs?: number; opsPerSecond: number; dataSize?: number }> {
    // Warmup
    for (let i = 0; i < WARMUP_ITERATIONS; i++) {
        operation();
    }

    // Actual benchmark
    const start = performance.now();
    for (let i = 0; i < iterations; i++) {
        operation();
    }
    const elapsed = performance.now() - start;

    const avgTime = elapsed / iterations;
    const opsPerSecond = 1000 / avgTime;

    return {
        avgTime,
        opsPerSecond,
    };
}

// Hash function benchmarks
Deno.bench("SHA256 hash - 1KB data", { group: "hash-sha256" }, async () => {
    await setupOpenSSL();

    const data = crypto.getRandomValues(new Uint8Array(1024));
    const result = await runBenchmark("SHA256-1KB", () => {
        openssl!.hash(data, 'SHA256');
    }, SMALL_ITERATIONS);

    const throughput = (1024 / result.avgTime * 1000) / (1024 * 1024);
    console.log(`SHA256 1KB: ${result.avgTime.toFixed(3)}ms, ${throughput.toFixed(1)} MB/s`);

    cleanupOpenSSL();
});

Deno.bench("SHA256 hash - 64KB data", { group: "hash-sha256" }, async () => {
    await setupOpenSSL();

    const data = crypto.getRandomValues(new Uint8Array(64 * 1024));
    const result = await runBenchmark("SHA256-64KB", () => {
        openssl!.hash(data, 'SHA256');
    }, BENCHMARK_ITERATIONS);

    const throughput = (64 * 1024 / result.avgTime * 1000) / (1024 * 1024);
    console.log(`SHA256 64KB: ${result.avgTime.toFixed(3)}ms, ${throughput.toFixed(1)} MB/s`);

    cleanupOpenSSL();
});

Deno.bench("SHA256 hash - 1MB data", { group: "hash-sha256" }, async () => {
    await setupOpenSSL();

    const data = crypto.getRandomValues(new Uint8Array(1024 * 1024));
    const result = await runBenchmark("SHA256-1MB", () => {
        openssl!.hash(data, 'SHA256');
    }, LARGE_ITERATIONS);

    const throughput = (1024 * 1024 / result.avgTime * 1000) / (1024 * 1024);
    console.log(`SHA256 1MB: ${result.avgTime.toFixed(3)}ms, ${throughput.toFixed(1)} MB/s`);

    cleanupOpenSSL();
});

Deno.bench("SHA512 hash - 64KB data", { group: "hash-sha512" }, async () => {
    await setupOpenSSL();

    const data = crypto.getRandomValues(new Uint8Array(64 * 1024));
    const result = await runBenchmark("SHA512-64KB", () => {
        openssl!.hash(data, 'SHA512');
    }, BENCHMARK_ITERATIONS);

    const throughput = (64 * 1024 / result.avgTime * 1000) / (1024 * 1024);
    console.log(`SHA512 64KB: ${result.avgTime.toFixed(3)}ms, ${throughput.toFixed(1)} MB/s`);

    cleanupOpenSSL();
});

Deno.bench("MD5 hash - 64KB data", { group: "hash-md5" }, async () => {
    await setupOpenSSL();

    const data = crypto.getRandomValues(new Uint8Array(64 * 1024));
    const result = await runBenchmark("MD5-64KB", () => {
        openssl!.hash(data, 'MD5');
    }, BENCHMARK_ITERATIONS);

    const throughput = (64 * 1024 / result.avgTime * 1000) / (1024 * 1024);
    console.log(`MD5 64KB: ${result.avgTime.toFixed(3)}ms, ${throughput.toFixed(1)} MB/s`);

    cleanupOpenSSL();
});

// AES encryption benchmarks
Deno.bench("AES-256-GCM encrypt - 1KB data", { group: "aes-gcm" }, async () => {
    await setupOpenSSL();

    const data = crypto.getRandomValues(new Uint8Array(1024));
    const key = crypto.getRandomValues(new Uint8Array(32));

    const result = await runBenchmark("AES-GCM-1KB", () => {
        openssl!.aesEncrypt(data, key, 'GCM');
    }, SMALL_ITERATIONS);

    const throughput = (1024 / result.avgTime * 1000) / (1024 * 1024);
    console.log(`AES-256-GCM 1KB: ${result.avgTime.toFixed(3)}ms, ${throughput.toFixed(1)} MB/s`);

    cleanupOpenSSL();
});

Deno.bench("AES-256-GCM encrypt - 64KB data", { group: "aes-gcm" }, async () => {
    await setupOpenSSL();

    const data = crypto.getRandomValues(new Uint8Array(64 * 1024));
    const key = crypto.getRandomValues(new Uint8Array(32));

    const result = await runBenchmark("AES-GCM-64KB", () => {
        openssl!.aesEncrypt(data, key, 'GCM');
    }, BENCHMARK_ITERATIONS);

    const throughput = (64 * 1024 / result.avgTime * 1000) / (1024 * 1024);
    console.log(`AES-256-GCM 64KB: ${result.avgTime.toFixed(3)}ms, ${throughput.toFixed(1)} MB/s`);

    cleanupOpenSSL();
});

Deno.bench("AES-256-GCM encrypt - 1MB data", { group: "aes-gcm" }, async () => {
    await setupOpenSSL();

    const data = crypto.getRandomValues(new Uint8Array(1024 * 1024));
    const key = crypto.getRandomValues(new Uint8Array(32));

    const result = await runBenchmark("AES-GCM-1MB", () => {
        openssl!.aesEncrypt(data, key, 'GCM');
    }, LARGE_ITERATIONS);

    const throughput = (1024 * 1024 / result.avgTime * 1000) / (1024 * 1024);
    console.log(`AES-256-GCM 1MB: ${result.avgTime.toFixed(3)}ms, ${throughput.toFixed(1)} MB/s`);

    cleanupOpenSSL();
});

Deno.bench("AES-256-CBC encrypt - 64KB data", { group: "aes-cbc" }, async () => {
    await setupOpenSSL();

    const data = crypto.getRandomValues(new Uint8Array(64 * 1024));
    const key = crypto.getRandomValues(new Uint8Array(32));

    const result = await runBenchmark("AES-CBC-64KB", () => {
        openssl!.aesEncrypt(data, key, 'CBC');
    }, BENCHMARK_ITERATIONS);

    const throughput = (64 * 1024 / result.avgTime * 1000) / (1024 * 1024);
    console.log(`AES-256-CBC 64KB: ${result.avgTime.toFixed(3)}ms, ${throughput.toFixed(1)} MB/s`);

    cleanupOpenSSL();
});

// RSA verification benchmarks
Deno.bench("RSA verification - 1KB data", { group: "rsa" }, async () => {
    await setupOpenSSL();

    const data = crypto.getRandomValues(new Uint8Array(1024));
    const signature = crypto.getRandomValues(new Uint8Array(256));
    const publicKey = crypto.getRandomValues(new Uint8Array(294));

    const result = await runBenchmark("RSA-1KB", () => {
        openssl!.rsaVerify(data, signature, publicKey);
    }, 50); // Fewer iterations for expensive operations

    console.log(`RSA verify 1KB: ${result.avgTime.toFixed(3)}ms, ${result.opsPerSecond.toFixed(1)} ops/s`);

    cleanupOpenSSL();
});

Deno.bench("RSA verification - 64KB data", { group: "rsa" }, async () => {
    await setupOpenSSL();

    const data = crypto.getRandomValues(new Uint8Array(64 * 1024));
    const signature = crypto.getRandomValues(new Uint8Array(256));
    const publicKey = crypto.getRandomValues(new Uint8Array(294));

    const result = await runBenchmark("RSA-64KB", () => {
        openssl!.rsaVerify(data, signature, publicKey);
    }, 20); // Even fewer iterations for large data

    console.log(`RSA verify 64KB: ${result.avgTime.toFixed(3)}ms, ${result.opsPerSecond.toFixed(1)} ops/s`);

    cleanupOpenSSL();
});

// EC point multiplication benchmarks
Deno.bench("EC point multiplication", { group: "ec" }, async () => {
    await setupOpenSSL();

    const point = new Uint8Array(65);
    point[0] = 0x04; // Uncompressed point
    crypto.getRandomValues(point.subarray(1));

    const scalar = crypto.getRandomValues(new Uint8Array(32));

    const result = await runBenchmark("EC-P256", () => {
        openssl!.ecPointMultiply(point, scalar);
    }, 20); // EC operations are expensive

    console.log(`EC P-256 point mul: ${result.avgTime.toFixed(3)}ms, ${result.opsPerSecond.toFixed(1)} ops/s`);

    cleanupOpenSSL();
});

// Memory allocation benchmarks
Deno.bench("Memory allocation stress test", { group: "memory" }, async () => {
    await setupOpenSSL();

    const result = await runBenchmark("Memory-stress", () => {
        // Allocate and process different sized data
        for (const size of [1024, 4096, 16384]) {
            const data = crypto.getRandomValues(new Uint8Array(size));
            openssl!.hash(data, 'SHA256');
        }
    }, 50);

    console.log(`Memory allocation: ${result.avgTime.toFixed(3)}ms per cycle`);

    cleanupOpenSSL();
});

// SIMD detection and comparison
Deno.bench("SIMD capability detection", { group: "simd" }, async () => {
    await setupOpenSSL();

    const simdSupported = openssl?.hasSIMD() ?? false;
    const stats = openssl?.getPerformanceStats() ?? { version: 'unknown', simdSupported: false, initialized: false, features: {} };

    console.log(`SIMD Detection: ${simdSupported ? 'Available' : 'Not Available'}`);
    console.log(`Features: ${JSON.stringify(stats.features)}`);

    // Test with data that should benefit from SIMD
    const largeData = crypto.getRandomValues(new Uint8Array(64 * 1024));

    if (openssl) {
        const start = performance.now();
        const hashResult = openssl!.hash(largeData, 'SHA256');
        const elapsed = performance.now() - start;

        console.log(`SHA256 64KB with SIMD=${hashResult.simdUsed}: ${elapsed.toFixed(3)}ms`);
    }

    cleanupOpenSSL();
});

// Run comprehensive performance report if executed directly
if (import.meta.main) {
    console.log('🚀 OpenSSL WASM Performance Report');
    console.log('===================================\n');

    await setupOpenSSL();

    console.log('📊 System Information:');
    if (openssl) {
        // @ts-ignore TypeScript has trouble with global variable typing
        const stats = openssl.getPerformanceStats();
        console.log(`   OpenSSL Version: ${stats.version}`);
        console.log(`   SIMD Support: ${stats.simdSupported ? '✅ Enabled' : '❌ Disabled'}`);
        console.log(`   Features: ${Object.keys(stats.features).filter(k => stats.features[k as keyof typeof stats.features]).join(', ')}`);
    } else {
        console.log('   OpenSSL not initialized');
    }

    // Memory info if available
    if ((performance as any).memory) {
        const mem = (performance as any).memory;
        console.log(`   JS Heap Used: ${(mem.usedJSHeapSize / 1024 / 1024).toFixed(1)} MB`);
        console.log(`   JS Heap Total: ${(mem.totalJSHeapSize / 1024 / 1024).toFixed(1)} MB`);
    }

    console.log('\n📈 Performance Summary:');
    console.log('   Run "deno bench" to see detailed benchmarks');
    console.log('   Use "deno bench --filter=hash" for specific categories');

    cleanupOpenSSL();
}