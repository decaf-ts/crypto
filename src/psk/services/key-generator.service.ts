import crypto, { KeyObject } from 'crypto';
import { BufferLike, toBuffer } from '../utils/encoding';

/**
 * @description Represents a generated key pair.
 * @interface GeneratedKeyPair
 * @property {KeyObject} publicKey - The generated public key.
 * @property {KeyObject} privateKey - The generated private key.
 * @memberOf module:@decaf-ts/crypto/psk
 */
export interface GeneratedKeyPair {
  publicKey: KeyObject;
  privateKey: KeyObject;
}

/**
 * @description A service for generating and managing cryptographic keys.
 * @summary This service provides methods for generating EC key pairs, exporting keys to PEM format, and normalizing keys to `KeyObject` instances.
 * @class KeyGeneratorService
 * @memberOf module:@decaf-ts/crypto/psk
 */
export class KeyGeneratorService {
  /**
   * @description Generates a new elliptic curve key pair.
   * @summary This method uses `crypto.generateKeyPairSync` to create a new EC key pair with the specified named curve.
   * @param {string} [namedCurve='secp256k1'] - The named elliptic curve to use for key generation.
   * @returns {GeneratedKeyPair} An object containing the generated public and private keys.
   * @function generateKeyPair
   * @memberOf module:@decaf-ts/crypto/psk
   */
  generateKeyPair(namedCurve = 'secp256k1'): GeneratedKeyPair {
    const keyPair = crypto.generateKeyPairSync('ec', { namedCurve });
    return {
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
    };
  }

  /**
   * @description Exports a private key to a PEM-encoded string.
   * @summary This method converts a private key (which can be a `KeyObject`, string, or Buffer) to its PEM representation in SEC1 format.
   * @param {crypto.KeyLike | BufferLike} value - The private key to export.
   * @returns {string} The PEM-encoded private key string.
   * @function exportPrivateKey
   * @memberOf module:@decaf-ts/crypto/psk
   */
  exportPrivateKey(value: crypto.KeyLike | BufferLike): string {
    return this.toPrivateKeyObject(value).export({ format: 'pem', type: 'sec1' }).toString();
  }

  /**
   * @description Exports a public key to a PEM-encoded string.
   * @summary This method converts a public key (which can be a `KeyObject`, string, or Buffer) to its PEM representation in SPKI format.
   * @param {crypto.KeyLike | BufferLike} value - The public key to export.
   * @returns {string} The PEM-encoded public key string.
   * @function exportPublicKey
   * @memberOf module:@decaf-ts/crypto/psk
   */
  exportPublicKey(value: crypto.KeyLike | BufferLike): string {
    return this.toPublicKeyObject(value).export({ format: 'pem', type: 'spki' }).toString();
  }

  /**
   * @description Normalizes a private key to a `KeyObject`.
   * @summary This method converts a private key input into a Node.js `KeyObject`.
   * @param {crypto.KeyLike | BufferLike} value - The private key to normalize.
   * @returns {KeyObject} The normalized private key object.
   * @function normalizePrivateKey
   * @memberOf module:@decaf-ts/crypto/psk
   */
  normalizePrivateKey(value: crypto.KeyLike | BufferLike): KeyObject {
    return this.toPrivateKeyObject(value);
  }

  /**
   * @description Normalizes a public key to a `KeyObject`.
   * @summary This method converts a public key input into a Node.js `KeyObject`.
   * @param {crypto.KeyLike | BufferLike} value - The public key to normalize.
   * @returns {KeyObject} The normalized public key object.
   * @function normalizePublicKey
   * @memberOf module:@decaf-ts/crypto/psk
   */
  normalizePublicKey(value: crypto.KeyLike | BufferLike): KeyObject {
    return this.toPublicKeyObject(value);
  }

  /**
   * @description Converts a key input to a private `KeyObject`.
   * @summary This private helper method handles the conversion logic for private keys, supporting `KeyObject`, string (PEM), and Buffer (DER or PEM) inputs.
   * @param {crypto.KeyLike | BufferLike} value - The key input.
   * @returns {KeyObject} The private key object.
   * @function toPrivateKeyObject
   * @memberOf module:@decaf-ts/crypto/psk
   */
  private toPrivateKeyObject(value: crypto.KeyLike | BufferLike): KeyObject {
    if (this.isKeyObject(value)) {
      return value;
    }

    if (typeof value === 'string') {
      return crypto.createPrivateKey({ key: value, format: 'pem', type: 'sec1' });
    }

    const decoded = toBuffer(value);
    return this.createPrivateKeyFromBuffer(decoded);
  }

  /**
   * @description Converts a key input to a public `KeyObject`.
   * @summary This private helper method handles the conversion logic for public keys, supporting `KeyObject`, string (PEM), and Buffer (DER or PEM) inputs.
   * @param {crypto.KeyLike | BufferLike} value - The key input.
   * @returns {KeyObject} The public key object.
   * @function toPublicKeyObject
   * @memberOf module:@decaf-ts/crypto/psk
   */
  private toPublicKeyObject(value: crypto.KeyLike | BufferLike): KeyObject {
    if (this.isKeyObject(value)) {
      return value;
    }

    if (typeof value === 'string') {
      return crypto.createPublicKey({ key: value, format: 'pem', type: 'spki' });
    }

    const decoded = toBuffer(value);
    return this.createPublicKeyFromBuffer(decoded);
  }

  /**
   * @description Creates a private `KeyObject` from a Buffer.
   * @summary This private helper method attempts to create a private key from a buffer, trying DER format first and falling back to PEM if that fails.
   * @param {Buffer} buffer - The buffer containing the key data.
   * @returns {KeyObject} The private key object.
   * @function createPrivateKeyFromBuffer
   * @memberOf module:@decaf-ts/crypto/psk
   */
  private createPrivateKeyFromBuffer(buffer: Buffer): KeyObject {
    try {
      return crypto.createPrivateKey({ key: buffer, format: 'der', type: 'sec1' });
    } catch {
      return crypto.createPrivateKey({ key: buffer, format: 'pem', type: 'sec1' });
    }
  }

  /**
   * @description Creates a public `KeyObject` from a Buffer.
   * @summary This private helper method attempts to create a public key from a buffer, trying DER format first and falling back to PEM if that fails.
   * @param {Buffer} buffer - The buffer containing the key data.
   * @returns {KeyObject} The public key object.
   * @function createPublicKeyFromBuffer
   * @memberOf module:@decaf-ts/crypto/psk
   */
  private createPublicKeyFromBuffer(buffer: Buffer): KeyObject {
    try {
      return crypto.createPublicKey({ key: buffer, format: 'der', type: 'spki' });
    } catch {
      return crypto.createPublicKey({ key: buffer, format: 'pem', type: 'spki' });
    }
  }

  /**
   * @description Checks if a value is a `KeyObject`.
   * @summary This private helper method acts as a type guard to check if the provided value is an instance of `crypto.KeyObject`.
   * @param {unknown} value - The value to check.
   * @returns {boolean} True if the value is a `KeyObject`, false otherwise.
   * @function isKeyObject
   * @memberOf module:@decaf-ts/crypto/psk
   */
  private isKeyObject(value: unknown): value is KeyObject {
    return typeof value === 'object' && value instanceof KeyObject;
  }
}
