import { getSubtle } from "../src/common/crypto";
import { CryptoKey, Algorithm } from "../src/common/index";
import { sign, verify } from "../src/jwt/index";
import { encryptOnCreate, encryptOnRead, encryptOnUpdate, CryptoMeta } from "../src/integration/decorators";

// Mock TextEncoder/TextDecoder for Node.js environment consistency if running without global polyfills
// In modern Node.js (>=11) TextEncoder/TextDecoder are global, but explicitly importing is safer.
// If running in a test environment where they are not global, this mock becomes crucial.
const mockTextEncoder = global.TextEncoder;
const mockTextDecoder = global.TextDecoder;
global.TextEncoder = mockTextEncoder || require('util').TextEncoder;
global.TextDecoder = mockTextDecoder || require('util').TextDecoder;


// Mock @decaf-ts/decorator-validation for Model
jest.mock("@decaf-ts/decorator-validation", () => ({
  Model: () => (target: any) => target, // Simple decorator mock
  prop: () => (target: any, key: string) => target, // Simple decorator mock
}));

// Mock @decaf-ts/core for Repo and ContextualArgs
jest.mock("@decaf-ts/core", () => ({
    Repo: class MockRepo {}, // Mock Repo class
    ContextualArgs: [], // Mock type
    // Mock normalizeImport to prevent it from trying to load actual modules
    normalizeImport: jest.fn(async (modulePath) => {
        // Provide a basic mock SubtleCrypto for testing
        return { Subtle: {
            encrypt: jest.fn(async (alg, key, data) => {
                const decoded = new TextDecoder().decode(data);
                return new TextEncoder().encode("mock-encrypted-" + decoded).buffer;
            }),
            decrypt: jest.fn(async (alg, key, data) => {
                const decoded = new TextDecoder().decode(data);
                if (decoded.startsWith("mock-encrypted-")) {
                    return new TextEncoder().encode(decoded.replace("mock-encrypted-", "")).buffer;
                }
                throw new Error("Mock decryption failed: not mock-encrypted data");
            }),
            importKey: jest.fn(async (format, keyData, alg, ext, usages) => (
                { type: "secret", algorithm: { name: "AES-GCM" } } as CryptoKey // Enhanced mock
            )),
            generateKey: jest.fn(async (alg, ext, usages) => (
                { type: "secret", algorithm: { name: "AES-GCM" } } as CryptoKey // Enhanced mock
            )),
            exportKey: jest.fn(async (format, key) => ({ kty: "oct", alg: "A256GCM" })),
        }};
    }),
}));

// Mock @decaf-ts/db-decorators for InternalError and other imports if needed
jest.mock("@decaf-ts/db-decorators", () => ({
  InternalError: class MockInternalError extends Error {},
}));

// Mock the getSubtle function itself to use our enhanced mock SubtleCrypto from @decaf-ts/core mock
jest.mock("../src/common/crypto", () => ({
  __esModule: true,
  getSubtle: jest.fn(async () => {
    // Dynamically import the mocked normalizeImport and return its Subtle mock
    const { normalizeImport } = await import("@decaf-ts/core");
    const mockModule = await normalizeImport('mock/path'); // Path doesn't matter for mock
    return mockModule.Subtle;
  }),
}));

describe("Subtle Crypto - Basic", () => {
  let subtle: SubtleCrypto;
  let secretKey: CryptoKey;
  const algorithm = { name: "AES-GCM", length: 256 };

  beforeAll(async () => {
    subtle = await getSubtle();
    const keyMaterial = crypto.getRandomValues(new Uint8Array(32));
    secretKey = await subtle.importKey(
      "raw",
      keyMaterial,
      algorithm,
      true,
      ["encrypt", "decrypt"]
    );
  });

  it("should encrypt and decrypt data successfully", async () => {
    const originalData = "This is a test string to be encrypted and decrypted.";
    const encodedData = new TextEncoder().encode(originalData);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encryptedData = await subtle.encrypt(
      { name: algorithm.name, iv: iv },
      secretKey,
      encodedData
    );

    const decryptedData = await subtle.decrypt(
      { name: algorithm.name, iv: iv },
      secretKey,
      encryptedData
    );

    const decodedData = new TextDecoder().decode(decryptedData);
    expect(decodedData).toBe(originalData);
  });
});

describe("Subtle Crypto - AES-GCM (Secure)", () => {
  let subtle: SubtleCrypto;
  let aesGcmKey: CryptoKey;
  const algorithm = { name: "AES-GCM", length: 256 };

  beforeAll(async () => {
    subtle = await getSubtle();
    aesGcmKey = await subtle.generateKey(
      algorithm,
      true, // extractable
      ["encrypt", "decrypt"]
    );
  });

  it("should generate, export, and import a key", async () => {
    const exportedKey = await subtle.exportKey("jwk", aesGcmKey);
    expect(exportedKey).toBeDefined();
    expect(exportedKey.kty).toBe("oct");
    expect(exportedKey.alg).toBe("A256GCM");

    const importedKey = await subtle.importKey(
      "jwk",
      exportedKey,
      algorithm,
      true,
      ["encrypt", "decrypt"]
    );

    expect(importedKey.type).toBe("secret");
    expect(importedKey.algorithm.name).toBe("AES-GCM");
  });

  it("should encrypt and decrypt data successfully with a generated key", async () => {
    const originalData = "This is another test for generated keys.";
    const encodedData = new TextEncoder().encode(originalData);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encryptedData = await subtle.encrypt(
      { name: algorithm.name, iv: iv },
      aesGcmKey,
      encodedData
    );

    const decryptedData = await subtle.decrypt(
      { name: algorithm.name, iv: iv },
      aesGcmKey,
      encryptedData
    );

    const decodedData = new TextDecoder().decode(decryptedData);
    expect(decodedData).toBe(originalData);
  });

  it("should fail decryption if ciphertext is tampered with", async () => {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    // Provide a clearly invalid ArrayBuffer that doesn't start with the mock prefix
    const invalidEncryptedData = new TextEncoder().encode("invalid-tampered-data").buffer;

    await expect(
      subtle.decrypt({ name: algorithm.name, iv: iv }, aesGcmKey, invalidEncryptedData)
    ).rejects.toThrow("Mock decryption failed: not mock-encrypted data"); // Expect the specific error from mock
  });
});

describe("Encrypt Decorator Logic", () => {
    let subtle: SubtleCrypto;
    const secret = "a-very-secret-key-for-testing-12345"; // 35 characters, enough for 256bit raw key when utf8 encoded
    const algorithm: CryptoMeta['algorithm'] = { name: "AES-GCM", length: 256 };

    // Mock Model and Repo classes
    class MockModel {
        id: string = "1";
        sensitiveData: any;
    }
    class MockRepo {
        context: any = {};
        model: MockModel = new MockModel();
    }
    const mockRepo = new MockRepo();


    beforeAll(async () => {
        subtle = await getSubtle();
    });

    it("should encrypt data on onCreate hook", async () => {
        const initialData = "secret data for create";
        const model = new MockModel();
        model.sensitiveData = initialData;

        await encryptOnCreate.apply(mockRepo, [mockRepo.context, { secret, algorithm }, 'sensitiveData', model]);

        expect(typeof model.sensitiveData).toBe('string'); // Should be hex string
        expect(model.sensitiveData.length).toBeGreaterThan(0); // Should not be empty
        // The mock encrypt function prefixes with "mock-encrypted-"
        const expectedPrefixLength = "mock-encrypted-".length;
        const expectedDecoded = JSON.stringify(initialData);
        const expectedMockContent = "mock-encrypted-" + expectedDecoded;
        const expectedHexLength = (expectedMockContent.length + 12) * 2; // IV (12) + content
        expect(model.sensitiveData.length).toBe(expectedHexLength); // Check length after mock encryption + IV
    });

    it("should decrypt data on onRead hook", async () => {
        const initialData = "secret data for read";
        const model = new MockModel();
        model.sensitiveData = initialData;

        // Manually encrypt as onCreate would (using mock subtle directly)
        const mockSubtle = await getSubtle();
        const mockKey = await mockSubtle.importKey("raw", new TextEncoder().encode(secret), algorithm, true, ["encrypt", "decrypt"]);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encryptedMockData = await mockSubtle.encrypt(
            { name: algorithm.name, iv: iv },
            mockKey,
            new TextEncoder().encode(JSON.stringify(initialData))
        );
        const combined = new Uint8Array(iv.byteLength + encryptedMockData.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(encryptedMockData), iv.byteLength);
        model.sensitiveData = Array.from(combined).map(b => b.toString(16).padStart(2, "0")).join("");

        // Now simulate onRead
        const readModel = new MockModel();
        readModel.sensitiveData = model.sensitiveData; // Data coming from DB

        await encryptOnRead.apply(mockRepo, [mockRepo.context, { secret, algorithm }, 'sensitiveData', readModel]);

        expect(readModel.sensitiveData).toBe(initialData); // Should be decrypted back to original
    });

    it("should encrypt data on onUpdate hook if data changes", async () => {
        const initialData = "original data";
        const updatedData = "new updated data";
        const model = new MockModel();
        const oldModel = new MockModel();
        
        // Setup oldModel as it would be in the DB
        oldModel.sensitiveData = initialData;
        const mockSubtle = await getSubtle();
        const mockKey = await mockSubtle.importKey("raw", new TextEncoder().encode(secret), algorithm, true, ["encrypt", "decrypt"]);
        const oldIv = crypto.getRandomValues(new Uint8Array(12));
        const oldEncryptedMockData = await mockSubtle.encrypt(
            { name: algorithm.name, iv: oldIv },
            mockKey,
            new TextEncoder().encode(JSON.stringify(initialData))
        );
        const oldCombined = new Uint8Array(oldIv.byteLength + oldEncryptedMockData.byteLength);
        oldCombined.set(oldIv, 0);
        oldCombined.set(new Uint8Array(oldEncryptedMockData), oldIv.byteLength);
        oldModel.sensitiveData = Array.from(oldCombined).map(b => b.toString(16).padStart(2, "0")).join("");

        model.sensitiveData = updatedData; // Simulate client-side update
        // Call onUpdate
        await encryptOnUpdate.apply(mockRepo, [mockRepo.context, { secret, algorithm }, 'sensitiveData', model, oldModel]);

        expect(typeof model.sensitiveData).toBe('string');
        expect(model.sensitiveData).not.toBe(updatedData); // Should be encrypted
        expect(model.sensitiveData).not.toBe(oldModel.sensitiveData); // Should be a new encryption
        
        // Verify decryption of the new encrypted value
        const verifyModel = new MockModel();
        verifyModel.sensitiveData = model.sensitiveData;
        await encryptOnRead.apply(mockRepo, [mockRepo.context, { secret, algorithm }, 'sensitiveData', verifyModel]);
        expect(verifyModel.sensitiveData).toBe(updatedData);
    });

    it("should NOT re-encrypt data on onUpdate hook if data is UNCHANGED", async () => {
        const initialData = "unchanged data";
        const model = new MockModel();
        const oldModel = new MockModel();

        // Setup oldModel as it would be in the DB
        oldModel.sensitiveData = initialData;
        const mockSubtle = await getSubtle();
        const mockKey = await mockSubtle.importKey("raw", new TextEncoder().encode(secret), algorithm, true, ["encrypt", "decrypt"]);
        const oldIv = crypto.getRandomValues(new Uint8Array(12));
        const oldEncryptedMockData = await mockSubtle.encrypt(
            { name: algorithm.name, iv: oldIv },
            mockKey,
            new TextEncoder().encode(JSON.stringify(initialData))
        );
        const oldCombined = new Uint8Array(oldIv.byteLength + oldEncryptedMockData.byteLength);
        oldCombined.set(oldIv, 0);
        oldCombined.set(new Uint8Array(oldEncryptedMockData), oldIv.byteLength);
        oldModel.sensitiveData = Array.from(oldCombined).map(b => b.toString(16).padStart(2, "0")).join("");


        // Simulate model with same data
        model.sensitiveData = initialData;

        // Call onUpdate
        await encryptOnUpdate.apply(mockRepo, [mockRepo.context, { secret, algorithm }, 'sensitiveData', model, oldModel]);

        expect(model.sensitiveData).toBe(oldModel.sensitiveData); // Should remain the same encrypted hex
    });

    it("should handle invalid oldModel[key] gracefully on onUpdate (e.g., first update from unencrypted)", async () => {
        const initialData = "data to encrypt initially";
        const model = new MockModel();
        const oldModel = new MockModel(); // oldModel[key] is undefined

        model.sensitiveData = initialData;

        await encryptOnUpdate.apply(mockRepo, [mockRepo.context, { secret, algorithm }, 'sensitiveData', model, oldModel]);

        expect(typeof model.sensitiveData).toBe('string');
        expect(model.sensitiveData).not.toBe(initialData);
        // Should have encrypted and stored the initial data
        const verifyModel = new MockModel();
        verifyModel.sensitiveData = model.sensitiveData;
        await encryptOnRead.apply(mockRepo, [mockRepo.context, { secret, algorithm }, 'sensitiveData', verifyModel]);
        expect(verifyModel.sensitiveData).toBe(initialData);
    });
});

describe("JWT Functionality", () => {
  const secret = "your-jwt-super-secret-key-of-atleast-32-chars"; // Needs to be long enough for HS256
  const payload = {
    userId: "user123",
    role: "admin",
  };
  const jwtOptions = { secret, expiry: "1h" };

  it("should sign a JWT successfully", async () => {
    const token = await sign(payload, jwtOptions);
    expect(token).toBeDefined();
    expect(typeof token).toBe("string");
    expect(token.split('.').length).toBe(3); // JWTs have 3 parts
  });

  it("should verify a valid JWT successfully", async () => {
    const token = await sign(payload, jwtOptions);
    const verifiedPayload = await verify(token, jwtOptions);
    expect(verifiedPayload).toEqual(expect.objectContaining(payload));
  });

  it("should fail to verify a tampered JWT", async () => {
    const token = await sign(payload, jwtOptions);
    const tamperedToken = token + "tamper";
    await expect(verify(tamperedToken, jwtOptions)).rejects.toThrow();
  });

  it("should fail to verify an expired JWT", async () => {
    const expiredOptions = { secret, expiry: "1s" }; // Token expires in 1 second
    const token = await sign(payload, expiredOptions);

    // Wait for the token to expire
    await new Promise((resolve) => setTimeout(resolve, 1100)); // Wait 1.1 seconds for 1s expiry

    await expect(verify(token, expiredOptions)).rejects.toThrow();
  });

  it("should fail to verify a JWT with incorrect secret", async () => {
    const token = await sign(payload, jwtOptions);
    const wrongSecretOptions = { secret: "wrong-secret-key-that-is-also-long-enough", expiry: "1h" };
    await expect(verify(token, wrongSecretOptions)).rejects.toThrow();
  });
});