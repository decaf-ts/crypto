import { SubtleCrypto } from "./Subtle";
import { KeyUsage } from "./util-types";
import { CryptoKey } from "./crypto-types";
import { AesGcmParams } from "./aes-types";

/**
 * @description Converts an ArrayBuffer to a hex string.
 * @summary This function takes an ArrayBuffer and returns its hexadecimal string representation.
 * @param {ArrayBuffer} buffer - The ArrayBuffer to convert.
 * @returns {string} The hex string.
 * @function arrayBufferToHex
 * @memberOf module:@decaf-ts/crypto/common
 */
export function arrayBufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * @description Converts a hex string to an ArrayBuffer.
 * @summary This function takes a hexadecimal string and returns its ArrayBuffer representation.
 * @param {string} hexString - The hex string to convert.
 * @returns {ArrayBuffer} The ArrayBuffer.
 * @function hexToArrayBuffer
 * @memberOf module:@decaf-ts/crypto/common
 */
export function hexToArrayBuffer(hexString: string): ArrayBuffer {
  const bytes = new Uint8Array(hexString.length / 2);
  for (let i = 0; i < hexString.length; i += 2) {
    bytes[i / 2] = parseInt(hexString.substring(i, i + 2), 16);
  }
  return bytes.buffer;
}

/**
 * @description Derives a cryptographic key from a secret string.
 * @summary This function uses `subtle.importKey` to create a `CryptoKey` from a raw secret string. It's designed to be used in the CLI where algorithm parameters are provided as strings.
 * @param {SubtleCrypto} subtle - The `SubtleCrypto` implementation to use.
 * @param {string} secret - The secret string to derive the key from.
 * @param {string} algorithmName - The name of the algorithm.
 * @param {number} keyLength - The desired length of the key in bits.
 * @param {KeyUsage[]} keyUsages - The allowed usages for the new key.
 * @returns {Promise<CryptoKey>} A promise that resolves to the derived `CryptoKey`.
 * @function getDerivedKey
 * @memberOf module:@decaf-ts/crypto/common
 */
export async function getDerivedKey(
  subtle: SubtleCrypto,
  secret: string,
  algorithmName: string, // Changed to string for CLI input
  keyLength: number,
  keyUsages: KeyUsage[]
): Promise<CryptoKey> {
  const keyMaterial = new TextEncoder().encode(secret);
  return subtle.importKey(
    "raw",
    keyMaterial,
    { name: algorithmName, length: keyLength }, // Construct AlgorithmIdentifier
    true, // extractable
    keyUsages
  );
}

/**
 * @description Encrypts a string using AES-GCM.
 * @summary This function encrypts a plaintext string using the provided key and algorithm. It generates a random IV, performs the encryption, and returns a hex string containing the IV and the ciphertext.
 * @param {SubtleCrypto} subtle - The `SubtleCrypto` implementation to use.
 * @param {CryptoKey} key - The encryption key.
 * @param {string} algorithmName - The name of the algorithm (should be compatible with AES-GCM).
 * @param {string} plainText - The plaintext to encrypt.
 * @returns {Promise<string>} A promise that resolves to the encrypted content as a hex string (IV + ciphertext).
 * @function encryptContent
 * @memberOf module:@decaf-ts/crypto/common
 */
export async function encryptContent(
  subtle: SubtleCrypto,
  key: CryptoKey,
  algorithmName: string,
  plainText: string
): Promise<string> {
  const encodedData = new TextEncoder().encode(plainText);
  const iv = crypto.getRandomValues(new Uint8Array(12)); // Generate a random IV for AES-GCM

  const algorithm: AesGcmParams = { name: algorithmName, iv: iv };

  const encryptedData = await subtle.encrypt(algorithm, key, encodedData);
  const combined = new Uint8Array(iv.byteLength + encryptedData.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encryptedData), iv.byteLength);
  return arrayBufferToHex(combined.buffer);
}

/**
 * @description Decrypts a string that was encrypted with `encryptContent`.
 * @summary This function takes a hex string containing an IV and ciphertext, extracts them, and then performs decryption using the provided key and algorithm.
 * @param {SubtleCrypto} subtle - The `SubtleCrypto` implementation to use.
 * @param {CryptoKey} key - The decryption key.
 * @param {string} algorithmName - The name of the algorithm (should be compatible with AES-GCM).
 * @param {string} encryptedHex - The hex string to decrypt (IV + ciphertext).
 * @returns {Promise<string>} A promise that resolves to the decrypted plaintext string.
 * @function decryptContent
 * @memberOf module:@decaf-ts/crypto/common
 */
export async function decryptContent(
  subtle: SubtleCrypto,
  key: CryptoKey,
  algorithmName: string,
  encryptedHex: string
): Promise<string> {
  const combinedBuffer = hexToArrayBuffer(encryptedHex);
  // Assuming IV length is 12 bytes
  const iv = new Uint8Array(combinedBuffer, 0, 12);
  const encryptedData = new Uint8Array(combinedBuffer, 12);

  const algorithm: AesGcmParams = { name: algorithmName, iv: iv };

  const decryptedData = await subtle.decrypt(algorithm, key, encryptedData);
  return new TextDecoder().decode(decryptedData);
}
