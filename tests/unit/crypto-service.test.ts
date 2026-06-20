import { CryptoService } from "../../src/integration/services/CryptoService";

describe("CryptoService", () => {
  let cryptoService: CryptoService;
  let cryptoServiceCustom: CryptoService;
  let testKey: string;
  let testKeyBuffer: Buffer;

  beforeAll(async () => {
    cryptoService = new CryptoService();
    cryptoServiceCustom = new CryptoService();
    // Create a test key (32 bytes for AES-256)
    testKeyBuffer = Buffer.alloc(32, "test-key-32-bytes!");
    testKey = testKeyBuffer.toString("base64");
    // Initialize with default config
    await cryptoService.boot({});
    // Initialize with custom config (AES-128 and 16-byte IV)
    await cryptoServiceCustom.boot({
      aesGcm: { length: 128 },
      ivLength: 16,
    });
  });

  describe("deriveKeyFromSecret", () => {
    it("should derive a key from a secret string", async () => {
      const secret = "my-secret-password";
      const derivedKey = await cryptoService.deriveKeyFromSecret(secret);

      expect(derivedKey).toBeDefined();
      expect(typeof derivedKey).toBe("string");
      
      // Extract salt and key
      const buffer = Buffer.from(derivedKey, "base64");
      expect(buffer.length).toBe(48); // 16 bytes salt + 32 bytes key
    });

    it("should derive a key with provided salt", async () => {
      const secret = "my-secret-password";
      const salt = "dGVzdC1zYWx0LTEyMzQ1Ng=="; // base64 encoded 16 bytes
      const derivedKey = await cryptoService.deriveKeyFromSecret(secret, salt);

      expect(derivedKey).toBeDefined();
      
      // Verify salt is preserved
      const buffer = Buffer.from(derivedKey, "base64");
      const saltFromDerived = buffer.slice(0, 16).toString("base64");
      expect(saltFromDerived).toBe(salt);
    });

    it("should produce different keys for different secrets", async () => {
      const key1 = await cryptoService.deriveKeyFromSecret("secret1");
      const key2 = await cryptoService.deriveKeyFromSecret("secret2");

      expect(key1).not.toBe(key2);
    });

    it("should produce same key for same secret and salt", async () => {
      const secret = "my-secret-password";
      const salt = "dGVzdC1zYWx0LTEyMzQ1Ng==";
      
      const key1 = await cryptoService.deriveKeyFromSecret(secret, salt);
      const key2 = await cryptoService.deriveKeyFromSecret(secret, salt);

      expect(key1).toBe(key2);
    });
  });

  describe("extractKeyFromDerivedKey", () => {
    it("should extract salt and key from derived key", () => {
      const derivedKey = "AAAAAAAAAAAAAAAAAAAAAA" + // 16 bytes of zeros (salt)
                        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"; // 16 bytes of B's (first half of key)
      // This is just testing the extraction logic, not actual crypto
      
      const result = cryptoService.extractKeyFromDerivedKey(derivedKey);
      
      expect(result).toBeDefined();
      expect(result.salt).toBeDefined();
      expect(result.key).toBeDefined();
      expect(typeof result.salt).toBe("string");
      expect(typeof result.key).toBe("string");
    });

    it("should correctly split at 16 bytes", () => {
      const fullKey = Buffer.concat([
        Buffer.from("0123456789abcdef", "utf8"), // 16 bytes salt
        Buffer.from("fedcba9876543210fedcba9876543210", "hex") // 32 bytes key
      ]).toString("base64");
      
      const result = cryptoService.extractKeyFromDerivedKey(fullKey);
      
      expect(result.salt).toBe("MDEyMzQ1Njc4OWFiY2RlZg=="); // "0123456789abcdef" in base64
    });
  });

  describe("encrypt / decrypt (simple API)", () => {
    it("should encrypt and decrypt a string payload with secret", async () => {
      const payload = "This is a secret message";
      const secret = "my-secret-password";
      
      const result = await cryptoService.encrypt(payload, secret);
      
      expect(result.encryptedData).toBeDefined();
      expect(result.iv).toBeDefined();
      expect(result.salt).toBeDefined();
      
      // Verify encryption produced different output
      expect(result.encryptedData).not.toBe(payload);
      expect(result.encryptedData).toContain("=="); // base64 padding
      
      // Decrypt and verify
      const decrypted = await cryptoService.decrypt(result.encryptedData, secret, result.salt);
      expect(decrypted).toBe(payload);
    });

    it("should encrypt and decrypt JSON payload", async () => {
      const payload = JSON.stringify({ apiKey: "abc123", secret: "xyz789" });
      const secret = "another-secret";
      
      const result = await cryptoService.encrypt(payload, secret);
      const decrypted = await cryptoService.decrypt(result.encryptedData, secret, result.salt);
      
      expect(JSON.parse(decrypted)).toEqual(JSON.parse(payload));
    });

    it("should fail decryption with wrong secret", async () => {
      const payload = "secret data";
      const secret = "correct-secret";
      const wrongSecret = "wrong-secret";
      
      const result = await cryptoService.encrypt(payload, secret);
      
      await expect(cryptoService.decrypt(result.encryptedData, wrongSecret, result.salt))
        .rejects.toThrow();
    });

    it("should fail decryption with tampered data", async () => {
      const payload = "secret data";
      const secret = "my-secret";
      
      const result = await cryptoService.encrypt(payload, secret);
      
      // Tamper with the encrypted data
      const tampered = result.encryptedData.slice(0, -4) + "====";
      
      await expect(cryptoService.decrypt(tampered, secret, result.salt))
        .rejects.toThrow();
    });

    it("should produce different IVs for same payload", async () => {
      const payload = "same payload";
      const secret = "same-secret";
      
      const result1 = await cryptoService.encrypt(payload, secret);
      const result2 = await cryptoService.encrypt(payload, secret);
      
      // IVs should be different
      expect(result1.iv).not.toBe(result2.iv);
      
      // Both should decrypt correctly
      const decrypted1 = await cryptoService.decrypt(result1.encryptedData, secret, result1.salt);
      const decrypted2 = await cryptoService.decrypt(result2.encryptedData, secret, result2.salt);
      
      expect(decrypted1).toBe(payload);
      expect(decrypted2).toBe(payload);
    });
  });

  describe("encryptPayload / decryptPayload (low-level API)", () => {
    it("should encrypt and decrypt with pre-derived key", async () => {
      const payload = "This is a secret message";
      const { encryptedData, metadata } = await cryptoService.encryptPayload(payload, "key-1", testKey);
      
      expect(encryptedData).toBeDefined();
      expect(metadata.keyId).toBe("key-1");
      expect(metadata.iv).toBeDefined();
      
      const decrypted = await cryptoService.decryptPayload(encryptedData, testKey);
      expect(decrypted).toBe(payload);
    });
  });

  describe("Integration: derive, encrypt, decrypt flow", () => {
    it("should derive key, encrypt with it, then decrypt with extracted key", async () => {
      const secret = "my-master-secret";
      const payload = "sensitive-data-to-protect";
      
      const derivedKey = await cryptoService.deriveKeyFromSecret(secret);
      const { salt, key } = cryptoService.extractKeyFromDerivedKey(derivedKey);
      const { encryptedData } = await cryptoService.encryptPayload(payload, "derived-key", key);
      const decrypted = await cryptoService.decryptPayload(encryptedData, key);
      
      expect(decrypted).toBe(payload);
      
      const derivedBuffer = Buffer.from(derivedKey, "base64");
      const extractedSalt = derivedBuffer.slice(0, 16).toString("base64");
      expect(extractedSalt).toBe(salt);
    });

    it("should use simple encrypt/decrypt API", async () => {
      const secret = "simple-secret";
      const payload = "simple-payload";
      
      const result = await cryptoService.encrypt(payload, secret);
      expect(result.encryptedData).toBeDefined();
      expect(result.iv).toBeDefined();
      expect(result.salt).toBeDefined();
      
      const decrypted = await cryptoService.decrypt(result.encryptedData, secret, result.salt);
      expect(decrypted).toBe(payload);
    });

    it("should demonstrate .for() API for switching between configs", async () => {
      const secret = "config-switch-test";
      const payload = "test-payload";
      const iterations = 50;

      const mixedConfigTimeStart = Date.now();
      const baseService = new CryptoService();
      await baseService.boot({ aesGcm: { length: 256 } });
      
      for (let i = 0; i < iterations; i++) {
        if (i % 2 === 0) {
          await baseService.for({ aesGcm: { length: 128 } }).encrypt(payload, secret);
        } else {
          await baseService.for({ aesGcm: { length: 192 } }).encrypt(payload, secret);
        }
      }
      const mixedConfigTime = Date.now() - mixedConfigTimeStart;

      const singleConfigTimeStart = Date.now();
      const service128 = new CryptoService();
      await service128.boot({ aesGcm: { length: 128 } });
      const service256 = new CryptoService();
      await service256.boot({ aesGcm: { length: 256 } });
      
      for (let i = 0; i < iterations; i++) {
        if (i % 2 === 0) {
          await service128.encrypt(payload, secret);
        } else {
          await service256.encrypt(payload, secret);
        }
      }
      const singleConfigTime = Date.now() - singleConfigTimeStart;

      expect(mixedConfigTime).toBeLessThanOrEqual(singleConfigTime + 50);
      console.log(`Using .for() to switch configs: ${mixedConfigTime}ms vs ${singleConfigTime}ms for separate services`);
    });
  });

  describe("Error handling", () => {
    it("should throw InternalError on encryption failure with invalid key", async () => {
      const payload = "test";
      const invalidKey = "not-base64-key!";
      
      await expect(cryptoService.encryptPayload(payload, "key", invalidKey))
        .rejects.toThrow("Failed to encrypt");
    });

    it("should throw InternalError on decryption failure with invalid data", async () => {
      const invalidData = "not-valid-base64-encrypted-data!";
      
      await expect(cryptoService.decryptPayload(invalidData, testKey))
        .rejects.toThrow("Failed to decrypt");
    });
  });

  describe("Configuration", () => {
    it("should use custom AES-GCM length and IV length when configured", async () => {
      const payload = "test payload for custom config";
      
      // Encrypt with custom config (AES-128, 16-byte IV)
      const { encryptedData, metadata } = await cryptoServiceCustom.encryptPayload(
        payload,
        "custom-key",
        testKey
      );
      
      expect(metadata.iv).toBeDefined();
      // IV should be 16 bytes = 32 hex chars (base64 encoded)
      const ivBuffer = Buffer.from(metadata.iv, "base64");
      expect(ivBuffer.length).toBe(16);
      
      // Decrypt and verify
      const decrypted = await cryptoServiceCustom.decryptPayload(encryptedData, testKey);
      expect(decrypted).toBe(payload);
    });

    it("should use default AES-256 and 12-byte IV when no config provided", async () => {
      const payload = "test payload for default config";
      
      const { encryptedData, metadata } = await cryptoService.encryptPayload(
        payload,
        "default-key",
        testKey
      );
      
      expect(metadata.iv).toBeDefined();
      // Default IV should be 12 bytes = 16 base64 chars
      const ivBuffer = Buffer.from(metadata.iv, "base64");
      expect(ivBuffer.length).toBe(12);
      
      // Decrypt and verify
      const decrypted = await cryptoService.decryptPayload(encryptedData, testKey);
      expect(decrypted).toBe(payload);
    });
  });
});
