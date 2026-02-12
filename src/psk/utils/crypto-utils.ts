import crypto from 'crypto';
import { BufferLike, toBuffer } from './encoding';

const KEY_SIZES = [128, 192, 256];
const AUTHENTICATED_MODES = ['ocb', 'ccm', 'gcm'];

/**
 * @description Generates a salt from input data.
 * @summary This function creates a salt by hashing the input data with SHA-512 and taking a slice of the result.
 * @param {BufferLike} inputData - The data to generate the salt from.
 * @param {number} saltLen - The desired length of the salt.
 * @returns {Buffer} The generated salt.
 * @function generateSalt
 * @memberOf module:@decaf-ts/crypto/psk
 */
export function generateSalt(inputData: BufferLike, saltLen: number): Buffer {
  const hash = crypto.createHash('sha512');
  hash.update(toBuffer(inputData));
  const digestHex = hash.digest('hex');
  const digest = Buffer.from(digestHex, 'latin1');
  return Buffer.from(digest.subarray(0, saltLen));
}

/**
 * @description Gets the key length for a given algorithm.
 * @summary This function determines the key length in bytes for an algorithm by checking for the presence of '128', '192', or '256' in the algorithm name.
 * @param {string} algorithm - The algorithm name.
 * @returns {number} The key length in bytes.
 * @throws {Error} If the algorithm is invalid.
 * @function getKeyLength
 * @memberOf module:@decaf-ts/crypto/psk
 */
export function getKeyLength(algorithm: string): number {
  for (const size of KEY_SIZES) {
    if (algorithm.includes(size.toString())) {
      return size / 8;
    }
  }
  throw new Error('Invalid encryption algorithm.');
}

/**
 * @description Checks if an encryption algorithm is authenticated.
 * @summary This function checks if the algorithm name includes any of the authenticated modes ('ocb', 'ccm', 'gcm').
 * @param {string} algorithm - The algorithm name.
 * @returns {boolean} True if the algorithm is authenticated, false otherwise.
 * @function encryptionIsAuthenticated
 * @memberOf module:@decaf-ts/crypto/psk
 */
export function encryptionIsAuthenticated(algorithm: string): boolean {
  return AUTHENTICATED_MODES.some((mode) => algorithm.includes(mode));
}
