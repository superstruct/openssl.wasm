/**
 * OpenSSL WASM Basic Tests
 *
 * Tests core functionality including initialization, hash operations,
 * and basic cryptographic operations.
 *
 * Copyright 2025 Superstruct Ltd, New Zealand
 * Licensed under Apache-2.0
 */

import { assert, assertEquals, assertExists, assertNotEquals } from "@std/assert";
import OpenSSL from "../../src/lib/index.ts";

Deno.test("OpenSSL initialization", async () => {
    const openssl = new OpenSSL();

    // Should not be initialized initially
    assert(!openssl.isInitialized());

    // Initialize
    await openssl.initialize();

    // Should be initialized now
    assert(openssl.isInitialized());

    // Should have performance stats
    const stats = openssl.getPerformanceStats();
    assertExists(stats.version);
    assertEquals(stats.initialized, true);
    assert(typeof stats.simdSupported === 'boolean');

    openssl.cleanup();
    assert(!openssl.isInitialized());
});

Deno.test("OpenSSL double initialization", async () => {
    const openssl = new OpenSSL();

    // Initialize twice should not throw
    await openssl.initialize();
    await openssl.initialize(); // Should be safe to call again

    assert(openssl.isInitialized());

    openssl.cleanup();
});

Deno.test("SHA256 hash basic functionality", async () => {
    const openssl = new OpenSSL();
    await openssl.initialize();

    const testData = new TextEncoder().encode("Hello, World!");
    const result = openssl.hash(testData, 'SHA256');

    // Check result structure
    assertEquals(result.algorithm, 'SHA256');
    assertExists(result.hash);
    assertExists(result.hexHash);
    assert(typeof result.simdUsed === 'boolean');

    // SHA256 should produce 32 bytes
    assertEquals(result.hash.length, 32);

    // Hex string should be 64 characters
    assertEquals(result.hexHash.length, 64);

    // Result should be deterministic
    const result2 = openssl.hash(testData, 'SHA256');
    assertEquals(result.hexHash, result2.hexHash);

    openssl.cleanup();
});

Deno.test("SHA512 hash functionality", async () => {
    const openssl = new OpenSSL();
    await openssl.initialize();

    const testData = new TextEncoder().encode("Hello, World!");
    const result = openssl.hash(testData, 'SHA512');

    assertEquals(result.algorithm, 'SHA512');
    assertEquals(result.hash.length, 64); // SHA512 produces 64 bytes
    assertEquals(result.hexHash.length, 128); // 128 hex characters

    openssl.cleanup();
});

Deno.test("MD5 hash functionality", async () => {
    const openssl = new OpenSSL();
    await openssl.initialize();

    const testData = new TextEncoder().encode("Hello, World!");
    const result = openssl.hash(testData, 'MD5');

    assertEquals(result.algorithm, 'MD5');
    assertEquals(result.hash.length, 16); // MD5 produces 16 bytes
    assertEquals(result.hexHash.length, 32); // 32 hex characters

    openssl.cleanup();
});

Deno.test("Hash function with empty data", async () => {
    const openssl = new OpenSSL();
    await openssl.initialize();

    const emptyData = new Uint8Array(0);
    const result = openssl.hash(emptyData, 'SHA256');

    // Should handle empty data gracefully
    assertExists(result.hash);
    assertEquals(result.hash.length, 32);

    // Known SHA256 hash of empty string
    const expectedEmpty = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    assertEquals(result.hexHash, expectedEmpty);

    openssl.cleanup();
});

Deno.test("Hash function with large data", async () => {
    const openssl = new OpenSSL();
    await openssl.initialize();

    // Test with 1MB of data
    const largeData = new Uint8Array(1024 * 1024);
    for (let i = 0; i < largeData.length; i++) {
        largeData[i] = i & 0xFF;
    }

    const start = performance.now();
    const result = openssl.hash(largeData, 'SHA256');
    const elapsed = performance.now() - start;

    assertExists(result.hash);
    assertEquals(result.hash.length, 32);

    // Should complete in reasonable time (less than 1 second)
    assert(elapsed < 1000, `Hash took ${elapsed}ms, expected < 1000ms`);

    openssl.cleanup();
});

Deno.test("AES encryption basic functionality", async () => {
    const openssl = new OpenSSL();
    await openssl.initialize();

    const plaintext = new TextEncoder().encode("This is a test message for AES encryption");
    const key = crypto.getRandomValues(new Uint8Array(32)); // 256-bit key

    const result = openssl.aesEncrypt(plaintext, key, 'GCM');

    // Check result structure
    assertEquals(result.algorithm, 'AES-256-GCM');
    assertExists(result.data);
    assert(result.data.length > plaintext.length); // Should include IV and tag
    assert(typeof result.simdUsed === 'boolean');

    openssl.cleanup();
});

Deno.test("AES encryption with different modes", async () => {
    const openssl = new OpenSSL();
    await openssl.initialize();

    const plaintext = new TextEncoder().encode("Test message");
    const key = crypto.getRandomValues(new Uint8Array(32));

    // Test GCM mode
    const gcmResult = openssl.aesEncrypt(plaintext, key, 'GCM');
    assertEquals(gcmResult.algorithm, 'AES-256-GCM');

    // Test CBC mode
    const cbcResult = openssl.aesEncrypt(plaintext, key, 'CBC');
    assertEquals(cbcResult.algorithm, 'AES-256-CBC');

    // Results should be different
    assertNotEquals(gcmResult.data, cbcResult.data);

    openssl.cleanup();
});

Deno.test("RSA verification mock test", async () => {
    const openssl = new OpenSSL();
    await openssl.initialize();

    const data = new TextEncoder().encode("Test data for RSA verification");
    const mockSignature = crypto.getRandomValues(new Uint8Array(256));
    const mockPublicKey = crypto.getRandomValues(new Uint8Array(294));

    const result = openssl.rsaVerify(data, mockSignature, mockPublicKey);

    // Should complete without throwing
    assertExists(result);
    assertEquals(result.algorithm, 'RSA');
    assert(typeof result.valid === 'boolean');
    assert(typeof result.simdUsed === 'boolean');

    openssl.cleanup();
});

Deno.test("EC point multiplication mock test", async () => {
    const openssl = new OpenSSL();
    await openssl.initialize();

    // Mock uncompressed P-256 point
    const mockPoint = new Uint8Array(65);
    mockPoint[0] = 0x04; // Uncompressed point indicator
    crypto.getRandomValues(mockPoint.subarray(1));

    const mockScalar = crypto.getRandomValues(new Uint8Array(32));

    const result = openssl.ecPointMultiply(mockPoint, mockScalar);

    // Should return a point (65 bytes for uncompressed P-256)
    assertEquals(result.length, 65);
    assertEquals(result[0], 0x04); // Should maintain uncompressed format

    openssl.cleanup();
});

Deno.test("Performance stats accuracy", async () => {
    const openssl = new OpenSSL();

    // Before initialization
    let stats = openssl.getPerformanceStats();
    assertEquals(stats.initialized, false);

    // After initialization
    await openssl.initialize();
    stats = openssl.getPerformanceStats();
    assertEquals(stats.initialized, true);
    assertEquals(stats.version, '3.3.2');
    assertExists(stats.features);
    assert(stats.features.aes);
    assert(stats.features.rsa);
    assert(stats.features.ecc);
    assert(stats.features.sha);

    openssl.cleanup();
});

Deno.test("Error handling - uninitialized operations", async () => {
    const openssl = new OpenSSL();

    const testData = new TextEncoder().encode("test");

    try {
        openssl.hash(testData, 'SHA256');
        assert(false, "Should have thrown error for uninitialized OpenSSL");
    } catch (error) {
        assert(error instanceof Error);
        assert(error.message.includes('not initialized'));
    }
});

Deno.test("Error handling - invalid parameters", async () => {
    const openssl = new OpenSSL();
    await openssl.initialize();

    const testData = new TextEncoder().encode("test");
    const validKey = crypto.getRandomValues(new Uint8Array(32));
    const invalidKey = crypto.getRandomValues(new Uint8Array(16)); // Wrong size

    try {
        openssl.aesEncrypt(testData, invalidKey, 'GCM');
        assert(false, "Should have thrown error for invalid key size");
    } catch (error) {
        assert(error instanceof Error);
        assert(error.message.includes('32-byte key'));
    }

    openssl.cleanup();
});

Deno.test("Memory cleanup", async () => {
    const openssl = new OpenSSL();
    await openssl.initialize();

    // Perform some operations
    const testData = new Uint8Array(1024 * 1024); // 1MB
    openssl.hash(testData, 'SHA256');

    // Cleanup should work without errors
    openssl.cleanup();
    assert(!openssl.isInitialized());

    // Multiple cleanups should be safe
    openssl.cleanup();
});