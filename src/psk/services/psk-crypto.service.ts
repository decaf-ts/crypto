import crypto from 'crypto';
import type { KeyObject } from 'crypto';
import { encode as base58Encode, decode as base58Decode } from '../utils/base58';
import { decodeBase64, encodeBase64, encodeBase64UrlSafe } from '../utils/base64';
import { BufferLike, toBuffer } from '../utils/encoding';
import { generateSalt, getKeyLength } from '../utils/crypto-utils';
import { dumpObjectForHashing, hashValues } from '../utils/ssutil';
import { KeyGeneratorService, GeneratedKeyPair } from './key-generator.service';
import { PskHash } from '../models/psk-hash';

/**
 * @description Represents a cryptographic key in various forms.
 * @summary This type can be a Buffer, an ArrayBuffer, an ArrayBufferView, a string (PEM-encoded), or a Node.js `KeyObject`.
 * @typedef {BufferLike | KeyObject} PskKeyLike
 * @memberOf module:@decaf-ts/crypto/psk
 */
export type PskKeyLike = BufferLike | KeyObject;

/**
 * @description A service providing various cryptographic utilities.
 * @summary This service encapsulates a wide range of cryptographic operations, including key pair generation, signing, verification, hashing, key derivation, and random byte/string generation. It also provides utilities for Base58 and Base64 encoding/decoding, and object hashing.
 * @class PskCryptoService
 * @memberOf module:@decaf-ts/crypto/psk
 */
export class PskCryptoService {
  private readonly keyGenerator = new KeyGeneratorService();
  private readonly uidAlphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

  /**
   * @description Generates a new elliptic curve key pair.
   * @summary This method uses the internal `KeyGeneratorService` to create a new EC key pair with the specified named curve.
   * @param {string} [namedCurve='secp256k1'] - The named elliptic curve to use for key generation.
   * @returns {GeneratedKeyPair} An object containing the generated public and private keys.
   * @function generateKeyPair
   * @memberOf module:@decaf-ts/crypto/psk
   */
  generateKeyPair(namedCurve = 'secp256k1'): GeneratedKeyPair {
    return this.keyGenerator.generateKeyPair(namedCurve);
  }

  /**
   * @description Converts `PskKeyLike` inputs to PEM-encoded string representations of private and public keys.
   * @summary This method takes a private key and a public key, which can be in various formats (`BufferLike`, string, or `KeyObject`), and exports them into their standard PEM string formats.
   * @param {PskKeyLike} privateKey - The private key to convert.
   * @param {PskKeyLike} publicKey - The public key to convert.
   * @returns {{ privateKey: string; publicKey: string }} An object containing the PEM-encoded private and public keys.
   * @function convertKeys
   * @memberOf module:@decaf-ts/crypto/psk
   */
  convertKeys(privateKey: PskKeyLike, publicKey: PskKeyLike): { privateKey: string; publicKey: string } {
    return {
      privateKey: this.keyGenerator.exportPrivateKey(privateKey),
      publicKey: this.keyGenerator.exportPublicKey(publicKey),
    };
  }

  /**
   * @description Signs data using the specified algorithm and private key.
   * @summary This method creates a digital signature for the given data using the provided algorithm (e.g., 'sha256') and the private key.
   * @param {string} algorithm - The signing algorithm (e.g., 'sha256').
   * @param {BufferLike} data - The data to be signed.
   * @param {PskKeyLike} privateKey - The private key used for signing.
   * @returns {Buffer} The generated signature as a Buffer.
   * @function sign
   * @memberOf module:@decaf-ts/crypto/psk
   */
  sign(algorithm: string, data: BufferLike, privateKey: PskKeyLike): Buffer {
    const signer = crypto.createSign(algorithm);
    signer.update(toBuffer(data));
    signer.end();
    return signer.sign(this.keyGenerator.normalizePrivateKey(privateKey));
  }

  /**
   * @description Verifies a digital signature.
   * @summary This method verifies if the given signature is valid for the provided data and public key, using the specified algorithm.
   * @param {string} algorithm - The verification algorithm (e.g., 'sha256').
   * @param {BufferLike} data - The original data that was signed.
   * @param {PskKeyLike} publicKey - The public key used for verification.
   * @param {Buffer} signature - The digital signature to verify.
   * @returns {boolean} True if the signature is valid, false otherwise.
   * @function verify
   * @memberOf module:@decaf-ts/crypto/psk
   */
  verify(algorithm: string, data: BufferLike, publicKey: PskKeyLike, signature: Buffer): boolean {
    const verifier = crypto.createVerify(algorithm);
    verifier.update(toBuffer(data));
    verifier.end();
    return verifier.verify(this.keyGenerator.normalizePublicKey(publicKey), signature);
  }

  /**
   * @description Hashes a readable stream using the PSK hashing mechanism.
   * @summary This method reads data from a `NodeJS.ReadableStream`, updates a `PskHash` instance with each chunk, and resolves with the final hash. An optional callback can be provided.
   * @param {NodeJS.ReadableStream} readStream - The readable stream to hash.
   * @param {function(Error | null, Buffer?): void} [callback] - An optional callback function to handle the result or errors.
   * @returns {Promise<Buffer>} A promise that resolves to the hash as a Buffer.
   * @function pskHashStream
   * @memberOf module:@decaf-ts/crypto/psk
   */
  async pskHashStream(readStream: NodeJS.ReadableStream, callback?: (err: Error | null, hash?: Buffer) => void): Promise<Buffer> {
    return new Promise<Buffer>((resolve, reject) => {
      const pskHash = new PskHash();
      readStream.on('data', (chunk) => pskHash.update(chunk));
      readStream.on('end', () => {
        const result = pskHash.digest();
        callback?.(null, result as Buffer);
        resolve(result as Buffer);
      });
      readStream.on('error', (err) => {
        callback?.(err);
        reject(err);
      });
    });
  }

  /**
   * @description Hashes data using the PSK hashing mechanism (SHA-512 then SHA-256).
   * @summary This method computes a hash of the input data by first applying SHA-512 and then SHA-256 to the result.
   * @param {BufferLike} data - The data to hash.
   * @param {crypto.BinaryToTextEncoding} [encoding] - The encoding for the output hash. If not provided, a Buffer is returned.
   * @returns {Buffer | string} The computed hash as a Buffer or a string.
   * @function pskHash
   * @memberOf module:@decaf-ts/crypto/psk
   */
  pskHash(data: BufferLike, encoding?: crypto.BinaryToTextEncoding): Buffer | string {
    const hash = new PskHash();
    hash.update(toBuffer(data));
    return encoding ? hash.digest(encoding) : hash.digest();
  }

  /**
   * @description Hashes data using a specified algorithm.
   * @summary This method computes a hash of the input data using the provided algorithm (e.g., 'sha256', 'sha512').
   * @param {string} algorithm - The hashing algorithm to use.
   * @param {BufferLike} data - The data to hash.
   * @param {crypto.BinaryToTextEncoding} [encoding] - The encoding for the output hash. If not provided, a Buffer is returned.
   * @returns {Buffer | string} The computed hash as a Buffer or a string.
   * @function hash
   * @memberOf module:@decaf-ts/crypto/psk
   */
  hash(algorithm: string, data: BufferLike, encoding?: crypto.BinaryToTextEncoding): Buffer | string {
    const hash = crypto.createHash(algorithm);
    hash.update(toBuffer(data));
    return encoding ? hash.digest(encoding) : hash.digest();
  }

  /**
   * @description Hashes a JavaScript object.
   * @summary This method converts a JavaScript object into a canonical string representation and then hashes it using the specified algorithm.
   * @param {string} algorithm - The hashing algorithm to use.
   * @param {Record<string, unknown>} data - The object to hash.
   * @param {crypto.BinaryToTextEncoding} [encoding] - The encoding for the output hash. If not provided, a Buffer is returned.
   * @returns {Buffer | string} The computed hash as a Buffer or a string.
   * @function objectHash
   * @memberOf module:@decaf-ts/crypto/psk
   */
  objectHash(algorithm: string, data: Record<string, unknown>, encoding?: crypto.BinaryToTextEncoding): Buffer | string {
    return this.hash(algorithm, dumpObjectForHashing(data), encoding);
  }

  /**
   * @description Encodes data using Base58.
   * @summary This method converts input data into a Base58 encoded string.
   * @param {BufferLike} data - The data to encode.
   * @returns {string} The Base58 encoded string.
   * @function pskBase58Encode
   * @memberOf module:@decaf-ts/crypto/psk
   */
  pskBase58Encode(data: BufferLike): string {
    return base58Encode(data);
  }

  /**
   * @description Decodes a Base58 encoded string.
   * @summary This method converts a Base58 encoded string back into a Buffer.
   * @param {string} data - The Base58 encoded string to decode.
   * @returns {Buffer} The decoded data as a Buffer.
   * @function pskBase58Decode
   * @memberOf module:@decaf-ts/crypto/psk
   */
  pskBase58Decode(data: string): Buffer {
    return base58Decode(data);
  }

  /**
   * @description Encodes data using Base64.
   * @summary This method converts input data into a Base64 encoded string.
   * @param {BufferLike} data - The data to encode.
   * @returns {string} The Base64 encoded string.
   * @function pskBase64Encode
   * @memberOf module:@decaf-ts/crypto/psk
   */
  pskBase64Encode(data: BufferLike): string {
    return encodeBase64(data);
  }

  /**
   * @description Decodes a Base64 encoded string.
   * @summary This method converts a Base64 encoded string back into a Buffer.
   * @param {string} data - The Base64 encoded string to decode.
   * @returns {Buffer} The decoded data as a Buffer.
   * @function pskBase64Decode
   * @memberOf module:@decaf-ts/crypto/psk
   */
  pskBase64Decode(data: string): Buffer {
    return decodeBase64(data);
  }

  /**
   * @description Hashes arbitrary JavaScript values.
   * @summary This method converts arbitrary JavaScript values into a canonical string representation and then hashes it.
   * @param {unknown} values - The values to hash.
   * @returns {string} The computed hash as a hex string.
   * @function hashValues
   * @memberOf module:@decaf-ts/crypto/psk
   */
  hashValues(values: unknown): string {
    return hashValues(values);
  }

  /**
   * @description Generates a URL-safe unique identifier (UID).
   * @summary This method generates a UID by hashing a combination of an optional password and additional data, then encoding the result in a URL-safe Base64 format.
   * @param {BufferLike} [password] - An optional password to include in the hash.
   * @param {BufferLike} [additionalData] - Optional additional data to include in the hash.
   * @returns {string} The generated URL-safe UID.
   * @function generateSafeUid
   * @memberOf module:@decaf-ts/crypto/psk
   */
  generateSafeUid(password?: BufferLike, additionalData?: BufferLike): string {
    const basePassword = password ? toBuffer(password) : Buffer.alloc(0);
    const baseAdditional = additionalData ? toBuffer(additionalData) : Buffer.alloc(0);
    const digest = this.pskHash(Buffer.concat([basePassword, baseAdditional]));
    const digestBuffer = Buffer.isBuffer(digest) ? digest : toBuffer(digest);
    return encodeBase64UrlSafe(digestBuffer);
  }

  /**
   * @description Derives a key from a password using PBKDF2-HMAC-SHA256.
   * @summary This method uses PBKDF2 with SHA-256 to derive a cryptographic key from a password and a generated salt.
   * @param {string} algorithm - The algorithm for which the key length is determined.
   * @param {BufferLike} password - The password to derive the key from.
   * @param {number} [iterations=1000] - The number of iterations for PBKDF2.
   * @returns {Buffer} The derived key as a Buffer.
   * @throws {Error} If the password argument is not provided.
   * @function deriveKey
   * @memberOf module:@decaf-ts/crypto/psk
   */
  deriveKey(algorithm: string, password: BufferLike, iterations = 1000): Buffer {
    if (!password) {
      throw new Error('Password argument must be provided');
    }
    const keylen = getKeyLength(algorithm);
    const salt = generateSalt(password, 32);
    const normalizedPassword = toBuffer(password);
    return crypto.pbkdf2Sync(normalizedPassword, salt, iterations, keylen, 'sha256');
  }

  /**
   * @description Generates cryptographically strong pseudo-random bytes.
   * @summary This method generates a Buffer containing `len` cryptographically strong pseudo-random bytes.
   * @param {number} len - The number of bytes to generate.
   * @returns {Buffer} A Buffer containing the random bytes.
   * @throws {TypeError} If `len` is not a non-negative number.
   * @function randomBytes
   * @memberOf module:@decaf-ts/crypto/psk
   */
  randomBytes(len: number): Buffer {
    if (typeof len !== 'number' || len < 0) {
      throw new TypeError('Length must be a non-negative number');
    }
    return crypto.randomBytes(len);
  }

  /**
   * @description Generates a random string of a specified length.
   * @summary This method generates a string of random characters from a predefined alphabet, based on cryptographically strong pseudo-random bytes.
   * @param {number} len - The length of the random string to generate.
   * @returns {string} The generated random string.
   * @function randomString
   * @memberOf module:@decaf-ts/crypto/psk
   */
  randomString(len: number): string {
    const bytes = this.randomBytes(len);
    return Array.from(bytes)
      .map((value) => this.uidAlphabet[value % this.uidAlphabet.length])
      .join('');
  }

  /**
   * @description Performs a bitwise XOR operation on multiple buffers.
   * @summary This method takes an array of Buffers and performs a bitwise XOR operation on them. The result is stored in a new Buffer.
   * @param {Buffer[]} args - An array of Buffers to XOR.
   * @returns {Buffer} A new Buffer containing the result of the XOR operation.
   * @throws {Error} If less than two buffers are provided.
   * @function xorBuffers
   * @memberOf module:@decaf-ts/crypto/psk
   */
  xorBuffers(...args: Buffer[]): Buffer {
    if (args.length < 2) {
      throw new Error('xorBuffers requires at least two buffers');
    }
    const output = Buffer.from(args[args.length - 1]);
    for (let i = 0; i < args.length - 1; i += 1) {
      this.xorTwoBuffers(args[i], output);
    }
    return output;
  }

  PskHash = PskHash;

  /**
   * @description Generates a unique identifier (UID).
   * @summary This method generates a UID by creating a random string of a specified size.
   * @param {number} [size=32] - The desired length of the UID.
   * @returns {string} The generated UID.
   * @function generateUid
   * @memberOf module:@decaf-ts/crypto/psk
   */
  generateUid(size = 32): string {
    return this.randomString(size);
  }

  /**
   * @description Performs a bitwise XOR operation on two buffers in-place.
   * @summary This private helper method XORs the `source` buffer with the `target` buffer, modifying the `target` buffer.
   * @param {Buffer} source - The source buffer.
   * @param {Buffer} target - The target buffer to be modified.
   * @throws {TypeError} If inputs are not Buffers.
   * @function xorTwoBuffers
   * @memberOf module:@decaf-ts/crypto/psk
   */
  private xorTwoBuffers(source: Buffer, target: Buffer) {
    if (!Buffer.isBuffer(source) || !Buffer.isBuffer(target)) {
      throw new TypeError('xorBuffers expects Buffer inputs');
    }
    const length = Math.min(source.length, target.length);
    for (let i = 0; i < length; i += 1) {
      target[i] ^= source[i];
    }
  }
}
