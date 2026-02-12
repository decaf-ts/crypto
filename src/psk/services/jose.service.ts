import crypto from 'crypto';
import {
  CompactEncrypt,
  CompactJWEHeaderParameters,
  CompactJWSHeaderParameters,
  CompactSign,
  compactDecrypt,
  compactVerify,
} from 'jose';
import { BufferLike, toBuffer } from '../utils/encoding';

/**
 * @description Represents a cryptographic key in various forms for JOSE operations.
 * @summary This type can be a Buffer, a string (PEM-encoded), or a Node.js `KeyObject`.
 * @typedef {BufferLike | string | crypto.KeyObject} JoseKeyInput
 * @memberOf module:@decaf-ts/crypto/psk
 */
export type JoseKeyInput = BufferLike | string | crypto.KeyObject;

/**
 * @description Represents the result of a JOSE compact signing operation.
 * @interface JoseSignResult
 * @property {string} token - The generated JWS token.
 * @property {CompactJWSHeaderParameters} header - The protected header of the JWS.
 * @memberOf module:@decaf-ts/crypto/psk
 */
export interface JoseSignResult {
  token: string;
  header: CompactJWSHeaderParameters;
}

/**
 * @description Represents the result of a JOSE compact decryption or verification operation.
 * @interface JoseDecryptResult
 * @property {Buffer} plaintext - The decrypted or verified plaintext.
 * @property {CompactJWSHeaderParameters | CompactJWEHeaderParameters} header - The protected header of the JWS or JWE.
 * @memberOf module:@decaf-ts/crypto/psk
 */
export interface JoseDecryptResult {
  plaintext: Buffer;
  header: CompactJWSHeaderParameters | CompactJWEHeaderParameters;
}

/**
 * @description A service for JOSE (Javascript Object Signing and Encryption) operations.
 * @summary This service provides methods for compact signing, verification, encryption, and decryption of data using the `jose` library.
 * @class PskJoseService
 * @memberOf module:@decaf-ts/crypto/psk
 */
export class PskJoseService {
  /**
   * @description Creates a compact JWS (JSON Web Signature).
   * @summary This method signs a payload using a private key and returns the compact JWS token.
   * @param {BufferLike} payload - The payload to sign.
   * @param {JoseKeyInput} privateKey - The private key for signing.
   * @param {CompactJWSHeaderParameters} [header={ alg: 'ES256' }] - The protected header for the JWS.
   * @returns {Promise<JoseSignResult>} A promise that resolves to an object containing the JWS token and its header.
   * @function compactSign
   * @memberOf module:@decaf-ts/crypto/psk
   */
  async compactSign(
    payload: BufferLike,
    privateKey: JoseKeyInput,
    header: CompactJWSHeaderParameters = { alg: 'ES256' }
  ): Promise<JoseSignResult> {
    const signer = new CompactSign(toBuffer(payload)).setProtectedHeader(header);
    const token = await signer.sign(this.toPrivateKeyObject(privateKey));
    return { token, header };
  }

  /**
   * @description Verifies a compact JWS.
   * @summary This method verifies the signature of a JWS token using a public key and returns the plaintext payload.
   * @param {string} token - The JWS token to verify.
   * @param {JoseKeyInput} publicKey - The public key for verification.
   * @returns {Promise<JoseDecryptResult>} A promise that resolves to an object containing the plaintext and the protected header.
   * @function compactVerify
   * @memberOf module:@decaf-ts/crypto/psk
   */
  async compactVerify(token: string, publicKey: JoseKeyInput): Promise<JoseDecryptResult> {
    const { payload, protectedHeader } = await compactVerify(token, this.toPublicKeyObject(publicKey));
    return { plaintext: Buffer.from(payload), header: protectedHeader };
  }

  /**
   * @description Creates a compact JWE (JSON Web Encryption).
   * @summary This method encrypts a payload using a public key and returns the compact JWE token.
   * @param {BufferLike} payload - The payload to encrypt.
   * @param {JoseKeyInput} publicKey - The public key for encryption.
   * @param {CompactJWEHeaderParameters} [header={ alg: 'ECDH-ES+A256KW', enc: 'A256GCM' }] - The protected header for the JWE.
   * @returns {Promise<string>} A promise that resolves to the JWE token.
   * @function compactEncrypt
   * @memberOf module:@decaf-ts/crypto/psk
   */
  async compactEncrypt(
    payload: BufferLike,
    publicKey: JoseKeyInput,
    header: CompactJWEHeaderParameters = { alg: 'ECDH-ES+A256KW', enc: 'A256GCM' }
  ): Promise<string> {
    const encryptor = new CompactEncrypt(toBuffer(payload)).setProtectedHeader(header);
    return encryptor.encrypt(this.toPublicKeyObject(publicKey));
  }

  /**
   * @description Decrypts a compact JWE.
   * @summary This method decrypts a JWE token using a private key and returns the plaintext payload.
   * @param {string} token - The JWE token to decrypt.
   * @param {JoseKeyInput} privateKey - The private key for decryption.
   * @returns {Promise<JoseDecryptResult>} A promise that resolves to an object containing the plaintext and the protected header.
   * @function compactDecrypt
   * @memberOf module:@decaf-ts/crypto/psk
   */
  async compactDecrypt(token: string, privateKey: JoseKeyInput): Promise<JoseDecryptResult> {
    const { plaintext, protectedHeader } = await compactDecrypt(token, this.toPrivateKeyObject(privateKey));
    return { plaintext: Buffer.from(plaintext), header: protectedHeader };
  }

  /**
   * @description Converts a key input to a private `KeyObject`.
   * @summary This private helper method handles the conversion logic for private keys.
   * @param {JoseKeyInput} key - The private key input.
   * @returns {crypto.KeyObject} The private key object.
   * @function toPrivateKeyObject
   * @memberOf module:@decaf-ts/crypto/psk
   */
  private toPrivateKeyObject(key: JoseKeyInput): crypto.KeyObject {
    if (key instanceof crypto.KeyObject) {
      return key;
    }
    if (typeof key === 'string') {
      return crypto.createPrivateKey(key);
    }
    return crypto.createPrivateKey({ key: toBuffer(key), format: 'der', type: 'sec1' });
  }

  /**
   * @description Converts a key input to a public `KeyObject`.
   * @summary This private helper method handles the conversion logic for public keys.
   * @param {JoseKeyInput} key - The public key input.
   * @returns {crypto.KeyObject} The public key object.
   * @function toPublicKeyObject
   * @memberOf module:@decaf-ts/crypto/psk
   */
  private toPublicKeyObject(key: JoseKeyInput): crypto.KeyObject {
    if (key instanceof crypto.KeyObject) {
      return key;
    }
    if (typeof key === 'string') {
      return crypto.createPublicKey(key);
    }
    return crypto.createPublicKey({ key: toBuffer(key), format: 'der', type: 'spki' });
  }
}
