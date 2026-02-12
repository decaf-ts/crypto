import zlib from "zlib";
import { Crypto } from "./Crypto";

const MAGIC = Buffer.from("DECAF1", "ascii");
const SALT_BYTES = 16;
const IV_BYTES = 12;
const TAG_BYTES = 16;

/**
 * @description A class that provides static methods for obfuscating and deobfuscating data.
 * @summary The `Obfuscation` class uses `aes-256-gcm` with a key derived using `scrypt` to encrypt and decrypt data. It also uses `zlib` for compression before encryption and decompression after decryption. The class is designed to be used statically and has a private constructor to prevent instantiation.
 * @class Obfuscation
 * @example
 * const secret = "my-super-secret";
 * const data = Buffer.from("This is a secret message.");
 *
 * const obfuscatedData = Obfuscation.obfuscate(secret, data);
 * const deobfuscatedData = Obfuscation.deobfuscate(secret, obfuscatedData);
 *
 * console.log(deobfuscatedData.toString()); // "This is a secret message."
 */
export class Obfuscation {
  private constructor() {}

  /**
   * @description Gets the encryption key material from the environment variables.
   * @summary This function retrieves the `ENCRYPTION_KEY` from the process environment.
   * @returns {string} The encryption key material.
   * @function getKeyMaterial
   */
  static getKeyMaterial() {
    return process.env.ENCRYPTION_KEY || "";
  }

  /**
   * @description Derives an encryption key from a key material and a salt using scrypt.
   * @summary This function uses `crypto.scryptSync` to derive a 32-byte key.
   * @param {string} keyMaterial - The key material to derive the key from.
   * @param {Buffer} salt - The salt to use for the derivation.
   * @returns {Buffer} The derived key.
   * @function deriveKey
   */
  static deriveKey(keyMaterial: string, salt: Buffer) {
    return Crypto.scryptSync(keyMaterial, salt, 32);
  }

  /**
   * @description Obfuscates a buffer of data.
   * @summary This function compresses the input buffer using `zlib`, then encrypts it using `aes-256-gcm`. The resulting buffer is a concatenation of a magic number, salt, IV, authentication tag, and the ciphertext.
   * @param {string} secret - The secret to use for deriving the encryption key.
   * @param {Buffer} input - The buffer to obfuscate.
   * @returns {Buffer} The obfuscated buffer.
   * @function obfuscate
   * @mermaid
   * sequenceDiagram
   *   participant Client
   *   participant Obfuscation
   *   participant zlib
   *   participant crypto
   *
   *   Client->>Obfuscation: obfuscate(secret, input)
   *   Obfuscation->>crypto: randomBytes(SALT_BYTES)
   *   crypto-->>Obfuscation: salt
   *   Obfuscation->>crypto: randomBytes(IV_BYTES)
   *   crypto-->>Obfuscation: iv
   *   Obfuscation->>Obfuscation: deriveKey(secret, salt)
   *   Obfuscation-->>Obfuscation: key
   *   Obfuscation->>zlib: gzipSync(input)
   *   zlib-->>Obfuscation: gzipped
   *   Obfuscation->>crypto: createCipheriv("aes-256-gcm", key, iv)
   *   crypto-->>Obfuscation: cipher
   *   Obfuscation->>cipher: update(gzipped)
   *   cipher-->>Obfuscation: ciphertextPart1
   *   Obfuscation->>cipher: final()
   *   cipher-->>Obfuscation: ciphertextPart2
   *   Obfuscation->>cipher: getAuthTag()
   *   cipher-->>Obfuscation: tag
   *   Obfuscation->>Obfuscation: concat(MAGIC, salt, iv, tag, ciphertext)
   *   Obfuscation-->>Client: obfuscatedBuffer
   */
  static obfuscate(secret: string, input: Buffer) {
    const salt = Crypto.randomBytes(SALT_BYTES);
    const iv = Crypto.randomBytes(IV_BYTES);
    const key = this.deriveKey(secret, salt);
    const gzipped = zlib.gzipSync(input, { level: 9 });
    const cipher = Crypto.createCipheriv("aes-256-gcm", key, iv);
    const ciphertext = Buffer.concat([cipher.update(gzipped), cipher.final()]);
    const tag = cipher.getAuthTag();

    return Buffer.concat([MAGIC, salt, iv, tag, ciphertext]);
  }

  /**
   * @description Deobfuscates a buffer of data.
   * @summary This function deconstructs the input buffer to extract the magic number, salt, IV, authentication tag, and ciphertext. It then decrypts the ciphertext using `aes-256-gcm` and decompresses the result using `zlib`.
   * @param {string} secret - The secret to use for deriving the decryption key.
   * @param {Buffer} input - The buffer to deobfuscate.
   * @returns {Buffer} The deobfuscated buffer.
   * @throws {Error} If the input buffer is invalid (too short or has a bad magic number).
   * @function deobfuscate
   * @mermaid
   * sequenceDiagram
   *   participant Client
   *   participant Obfuscation
   *   participant zlib
   *   participant crypto
   *
   *   Client->>Obfuscation: deobfuscate(secret, input)
   *   Obfuscation->>Obfuscation: extract magic, salt, iv, tag, ciphertext from input
   *   Obfuscation->>Obfuscation: deriveKey(secret, salt)
   *   Obfuscation-->>Obfuscation: key
   *   Obfuscation->>crypto: createDecipheriv("aes-256-gcm", key, iv)
   *   crypto-->>Obfuscation: decipher
   *   Obfuscation->>decipher: setAuthTag(tag)
   *   Obfuscation->>decipher: update(ciphertext)
   *   decipher-->>Obfuscation: plaintextPart1
   *   Obfuscation->>decipher: final()
   *   decipher-->>Obfuscation: plaintextPart2
   *   Obfuscation->>zlib: gunzipSync(plaintext)
   *   zlib-->>Obfuscation: deobfuscatedBuffer
   *   Obfuscation-->>Client: deobfuscatedBuffer
   */
  static deobfuscate(secret: string, input: Buffer) {
    if (input.length < MAGIC.length + SALT_BYTES + IV_BYTES + TAG_BYTES) {
      throw new Error("Invalid prompt payload (too short)");
    }
    const magic = input.subarray(0, MAGIC.length);
    if (!magic.equals(MAGIC)) {
      throw new Error("Invalid prompt payload (bad magic)");
    }

    let offset = MAGIC.length;
    const salt = input.subarray(offset, offset + SALT_BYTES);
    offset += SALT_BYTES;
    const iv = input.subarray(offset, offset + IV_BYTES);
    offset += IV_BYTES;
    const tag = input.subarray(offset, offset + TAG_BYTES);
    offset += TAG_BYTES;
    const ciphertext = input.subarray(offset);

    const key = this.deriveKey(secret, salt);
    const decipher = Crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);
    return zlib.gunzipSync(plaintext);
  }
}
