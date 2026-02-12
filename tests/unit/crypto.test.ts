import { SubtleCrypto } from "../../src/common/Subtle";
import { getSubtle } from "../../src/common/crypto";
import { CryptoKey } from "../../src/common/index";
import { sign, verify } from "../../src/jwt/index";
import {
  encryptOnCreate,
  encryptOnRead,
  encryptOnUpdate,
  CryptoMeta,
} from "../../src/integration/decorators";

describe("Subtle Crypto - Basic", () => {
  let subtle: SubtleCrypto;
  let secretKey: CryptoKey;
  const algorithm = { name: "AES-GCM", length: 256 };

  beforeAll(async () => {
    subtle = await getSubtle();
    const keyMaterial = crypto.getRandomValues(new Uint8Array(32));
    secretKey = await subtle.importKey("raw", keyMaterial, algorithm, true, [
      "encrypt",
      "decrypt",
    ]);
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
    const invalidEncryptedData = new TextEncoder().encode(
      "invalid-tampered-data"
    ).buffer;

    await expect(
      subtle.decrypt(
        { name: algorithm.name, iv: iv },
        aesGcmKey,
        invalidEncryptedData
      )
    ).rejects.toThrow();
  });
});

describe("Encrypt Decorator Logic", () => {
  let subtle: SubtleCrypto;
  const secret = "a-very-secret-key-for-testing-12"; // exactly 32 bytes for AES-256 raw key
  const algorithm: CryptoMeta["algorithm"] = { name: "AES-GCM", length: 256 };

  // Mock Model and Repo classes
  class MockModel {
    id: string = "1";
    sensitiveData: any;
  }

  // Context without flags (no old model comparison)
  const plainContext: any = {};

  // Context with flags set (old model comparison enabled)
  const flaggedContext: any = {
    get: (key: string) => {
      if (key === "mergeForUpdate") return true;
      if (key === "applyUpdateValidation") return true;
      return undefined;
    },
  };

  class MockRepo {
    context: any = plainContext;
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

    await encryptOnCreate.apply(mockRepo, [
      mockRepo.context,
      { secret, algorithm },
      "sensitiveData",
      model,
    ]);

    expect(typeof model.sensitiveData).toBe("string"); // Should be hex string
    expect(model.sensitiveData.length).toBeGreaterThan(0); // Should not be empty

    // Decrypt to verify content
    const encryptedHex = model.sensitiveData;
    const iv = Buffer.from(encryptedHex.substring(0, 24), "hex"); // First 12 bytes (24 hex chars) are IV
    const ciphertextWithTag = Buffer.from(encryptedHex.substring(24), "hex");

    const decryptedData = await subtle.decrypt(
      { name: (algorithm as any).name, iv: iv },
      await subtle.importKey(
        "raw",
        new TextEncoder().encode(secret),
        algorithm,
        true,
        ["encrypt", "decrypt"]
      ),
      ciphertextWithTag
    );
    expect(new TextDecoder().decode(decryptedData)).toBe(
      JSON.stringify(initialData)
    );
  });

  it("should decrypt data on onRead hook", async () => {
    const initialData = "secret data for read";
    const model = new MockModel();
    model.sensitiveData = initialData;

    // Manually encrypt as onCreate would (using real subtle)
    const realSubtle = await getSubtle();
    const realKey = await realSubtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      algorithm,
      true,
      ["encrypt", "decrypt"]
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptedData = await realSubtle.encrypt(
      { name: (algorithm as any).name, iv: iv },
      realKey,
      new TextEncoder().encode(JSON.stringify(initialData))
    );
    const combined = new Uint8Array(iv.byteLength + encryptedData.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(encryptedData), iv.byteLength);
    model.sensitiveData = Array.from(combined)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    // Now simulate onRead
    const readModel = new MockModel();
    readModel.sensitiveData = model.sensitiveData; // Data coming from DB

    await encryptOnRead.apply(mockRepo, [
      mockRepo.context,
      { secret, algorithm },
      "sensitiveData",
      readModel,
    ]);

    expect(readModel.sensitiveData).toBe(initialData); // Should be decrypted back to original
  });

  it("should encrypt data on onUpdate hook if data changes", async () => {
    const initialData = "original data";
    const updatedData = "new updated data";
    const model = new MockModel();
    const oldModel = new MockModel();

    // In the real framework, afterRead has already decrypted oldModel,
    // so oldModel.sensitiveData is plaintext.
    oldModel.sensitiveData = initialData;
    model.sensitiveData = updatedData;

    // Call onUpdate with flagged context (old model comparison enabled)
    await encryptOnUpdate.apply(mockRepo, [
      flaggedContext,
      { secret, algorithm },
      "sensitiveData",
      model,
      oldModel,
    ]);

    expect(typeof model.sensitiveData).toBe("string");
    expect(model.sensitiveData).not.toBe(updatedData); // Should be encrypted

    // Verify decryption of the new encrypted value
    const verifyModel = new MockModel();
    verifyModel.sensitiveData = model.sensitiveData;
    await encryptOnRead.apply(mockRepo, [
      plainContext,
      { secret, algorithm },
      "sensitiveData",
      verifyModel,
    ]);
    expect(verifyModel.sensitiveData).toBe(updatedData);
  });

  it("should encrypt data on onUpdate hook even when data is UNCHANGED", async () => {
    const initialData = "unchanged data";
    const model = new MockModel();
    const oldModel = new MockModel();

    // In the real framework, afterRead has already decrypted oldModel,
    // so both model and oldModel contain plaintext.
    oldModel.sensitiveData = initialData;
    model.sensitiveData = initialData;

    // Call onUpdate with flagged context (old model comparison enabled)
    await encryptOnUpdate.apply(mockRepo, [
      flaggedContext,
      { secret, algorithm },
      "sensitiveData",
      model,
      oldModel,
    ]);

    // Even with identical plaintext, the value must be encrypted for storage.
    // A new random IV means a different ciphertext each time.
    expect(typeof model.sensitiveData).toBe("string");
    expect(model.sensitiveData).not.toBe(initialData);
    expect(model.sensitiveData.length).toBeGreaterThan(24);

    // Verify decryption still yields the original value
    const verifyModel = new MockModel();
    verifyModel.sensitiveData = model.sensitiveData;
    await encryptOnRead.apply(mockRepo, [
      plainContext,
      { secret, algorithm },
      "sensitiveData",
      verifyModel,
    ]);
    expect(verifyModel.sensitiveData).toBe(initialData);
  });

  it("should handle invalid oldModel[key] gracefully on onUpdate (e.g., first update from unencrypted)", async () => {
    const initialData = "data to encrypt initially";
    const model = new MockModel();
    const oldModel = new MockModel(); // oldModel[key] is undefined

    model.sensitiveData = initialData;

    await encryptOnUpdate.apply(mockRepo, [
      mockRepo.context,
      { secret, algorithm },
      "sensitiveData",
      model,
      oldModel,
    ]);

    expect(typeof model.sensitiveData).toBe("string");
    expect(model.sensitiveData).not.toBe(initialData);
    // Should have encrypted and stored the initial data
    const verifyModel = new MockModel();
    verifyModel.sensitiveData = model.sensitiveData;
    await encryptOnRead.apply(mockRepo, [
      mockRepo.context,
      { secret, algorithm },
      "sensitiveData",
      verifyModel,
    ]);
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
    expect(token.split(".").length).toBe(3); // JWTs have 3 parts
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
    const wrongSecretOptions = {
      secret: "wrong-secret-key-that-is-also-long-enough",
      expiry: "1h",
    };
    await expect(verify(token, wrongSecretOptions)).rejects.toThrow();
  });
});
