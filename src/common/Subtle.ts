import { HkdfParams, Pbkdf2Params } from "./pbkdf2-types";
import {
  AlgorithmIdentifier,
  BufferSource,
  KeyFormat,
  KeyUsage,
} from "./util-types";
import {
  AesCbcParams,
  AesCtrParams,
  AesDerivedKeyParams,
  AesGcmParams,
  AesKeyAlgorithm,
  AesKeyGenParams,
} from "./aes-types";
import { CryptoKey, CryptoKeyPair, JsonWebKey } from "./crypto-types";
import {
  EcdhKeyDeriveParams,
  EcdsaParams,
  EcKeyGenParams,
  EcKeyImportParams,
} from "./ec-types";
import {
  RsaHashedImportParams,
  RsaHashedKeyGenParams,
  RsaOaepParams,
  RsaPssParams,
} from "./rsa-types";
import { HmacImportParams, HmacKeyGenParams } from "./hmac-types";

/**
 * @description Provides a low-level interface for cryptographic operations.
 * @summary
 * The `SubtleCrypto` interface provides a set of methods for performing cryptographic
 * operations, including encryption, decryption, signing, verification, key generation,
 * key derivation, key import, and key export.
 *
 * This interface is designed to be used with the Web Crypto API and is implemented
 * by both browser and Node.js environments.
 * @interface SubtleCrypto
 * @memberOf module:@decaf-ts/crypto
 */
export interface SubtleCrypto {
  /**
   * @description Decrypts data.
   * @param {AesCbcParams | AesCtrParams | AesGcmParams | AlgorithmIdentifier | RsaOaepParams} algorithm - The algorithm to use for decryption.
   * @param {CryptoKey} key - The key to use for decryption.
   * @param {BufferSource} data - The data to decrypt.
   * @returns {Promise<ArrayBuffer>} A promise that resolves to the decrypted data.
   * @function decrypt
   * @memberOf module:@decaf-ts/crypto
   */
  decrypt(
    algorithm:
      | AesCbcParams
      | AesCtrParams
      | AesGcmParams
      | AlgorithmIdentifier
      | RsaOaepParams,
    key: CryptoKey,
    data: BufferSource
  ): Promise<ArrayBuffer>;

  /**
   * @description Derives a secret key from a master key.
   * @param {EcdhKeyDeriveParams | AlgorithmIdentifier | HkdfParams | Pbkdf2Params} algorithm - The algorithm to use for key derivation.
   * @param {CryptoKey} baseKey - The master key to use for derivation.
   * @param {number} [length] - The desired length of the derived key in bits.
   * @returns {Promise<ArrayBuffer>} A promise that resolves to the derived bits as an ArrayBuffer.
   * @function deriveBits
   * @memberOf module:@decaf-ts/crypto
   */
  deriveBits(
    algorithm:
      | EcdhKeyDeriveParams
      | AlgorithmIdentifier
      | HkdfParams
      | Pbkdf2Params,
    baseKey: CryptoKey,
    length?: number
  ): Promise<ArrayBuffer>;

  /**
   * @description Derives a secret key from a master key.
   * @param {EcdhKeyDeriveParams | AlgorithmIdentifier | HkdfParams | Pbkdf2Params} algorithm - The algorithm to use for key derivation.
   * @param {CryptoKey} baseKey - The master key to use for derivation.
   * @param {AesDerivedKeyParams | AlgorithmIdentifier | HkdfParams | HmacImportParams | Pbkdf2Params} derivedKeyType - The algorithm to use for the new key.
   * @param {boolean} extractable - Whether the new key can be extracted.
   * @param {KeyUsage[]} keyUsages - The allowed usages for the new key.
   * @returns {Promise<CryptoKey>} A promise that resolves to the new key.
   * @function deriveKey
   * @memberOf module:@decaf-ts/crypto
   */
  deriveKey(
    algorithm:
      | EcdhKeyDeriveParams
      | AlgorithmIdentifier
      | HkdfParams
      | Pbkdf2Params,
    baseKey: CryptoKey,
    derivedKeyType:
      | AesDerivedKeyParams
      | AlgorithmIdentifier
      | HkdfParams
      | HmacImportParams
      | Pbkdf2Params,
    extractable: boolean,
    keyUsages: KeyUsage[]
  ): Promise<CryptoKey>;

  /**
   * @description Derives a secret key from a master key.
   * @param {EcdhKeyDeriveParams | AlgorithmIdentifier | HkdfParams | Pbkdf2Params} algorithm - The algorithm to use for key derivation.
   * @param {CryptoKey} baseKey - The master key to use for derivation.
   * @param {AesDerivedKeyParams | AlgorithmIdentifier | HkdfParams | HmacImportParams | Pbkdf2Params} derivedKeyType - The algorithm to use for the new key.
   * @param {boolean} extractable - Whether the new key can be extracted.
   * @param {KeyUsage[]} keyUsages - The allowed usages for the new key.
   * @returns {Promise<CryptoKey>} A promise that resolves to the new key.
   * @function deriveKey
   * @memberOf module:@decaf-ts/crypto
   */
  deriveKey(
    algorithm:
      | EcdhKeyDeriveParams
      | AlgorithmIdentifier
      | HkdfParams
      | Pbkdf2Params,
    baseKey: CryptoKey,
    derivedKeyType:
      | AesDerivedKeyParams
      | AlgorithmIdentifier
      | HkdfParams
      | HmacImportParams
      | Pbkdf2Params,
    extractable: boolean,
    keyUsages: Iterable<KeyUsage>
  ): Promise<CryptoKey>;

  /**
   * @description Generates a digest of the given data.
   * @param {AlgorithmIdentifier} algorithm - The algorithm to use for the digest.
   * @param {BufferSource} data - The data to digest.
   * @returns {Promise<ArrayBuffer>} A promise that resolves to the digest.
   * @function digest
   * @memberOf module:@decaf-ts/crypto
   */
  digest(
    algorithm: AlgorithmIdentifier,
    data: BufferSource
  ): Promise<ArrayBuffer>;

  /**
   * @description Encrypts data.
   * @param {AesCbcParams | AesCtrParams | AesGcmParams | AlgorithmIdentifier | RsaOaepParams} algorithm - The algorithm to use for encryption.
   * @param {CryptoKey} key - The key to use for encryption.
   * @param {BufferSource} data - The data to encrypt.
   * @returns {Promise<ArrayBuffer>} A promise that resolves to the encrypted data.
   * @function encrypt
   * @memberOf module:@decaf-ts/crypto
   */
  encrypt(
    algorithm:
      | AesCbcParams
      | AesCtrParams
      | AesGcmParams
      | AlgorithmIdentifier
      | RsaOaepParams,
    key: CryptoKey,
    data: BufferSource
  ): Promise<ArrayBuffer>;

  /**
   * @description Exports a key.
   * @param {"jwk"} format - The format of the key to export.
   * @param {CryptoKey} key - The key to export.
   * @returns {Promise<JsonWebKey>} A promise that resolves to the exported key in JWK format.
   * @function exportKey
   * @memberOf module:@decaf-ts/crypto
   */
  exportKey(format: "jwk", key: CryptoKey): Promise<JsonWebKey>;

  /**
   * @description Exports a key.
   * @param {"raw" | "pkcs8" | "spki"} format - The format of the key to export.
   * @param {CryptoKey} key - The key to export.
   * @returns {Promise<ArrayBuffer>} A promise that resolves to the exported key as an ArrayBuffer.
   * @function exportKey
   * @memberOf module:@decaf-ts/crypto
   */
  exportKey(
    format: "raw" | "pkcs8" | "spki",
    key: CryptoKey
  ): Promise<ArrayBuffer>;

  /**
   * @description Exports a key.
   * @param {KeyFormat} format - The format of the key to export.
   * @param {CryptoKey} key - The key to export.
   * @returns {Promise<ArrayBuffer | JsonWebKey>} A promise that resolves to the exported key.
   * @function exportKey
   * @memberOf module:@decaf-ts/crypto
   */
  exportKey(
    format: KeyFormat,
    key: CryptoKey
  ): Promise<ArrayBuffer | JsonWebKey>;

  /**
   * @description Generates a new key or key pair.
   * @param {"Ed25519"} algorithm - The algorithm to use for key generation.
   * @param {boolean} extractable - Whether the new key can be extracted.
   * @param {string[]} keyUsages - The allowed usages for the new key.
   * @returns {Promise<CryptoKeyPair>} A promise that resolves to the new key pair.
   * @function generateKey
   * @memberOf module:@decaf-ts/crypto
   */
  generateKey(
    algorithm: "Ed25519",
    extractable: boolean,
    keyUsages: readonly ("sign" | "verify")[]
  ): Promise<CryptoKeyPair>;

  /**
   * @description Generates a new key or key pair.
   * @param {EcKeyGenParams | RsaHashedKeyGenParams} algorithm - The algorithm to use for key generation.
   * @param {boolean} extractable - Whether the new key can be extracted.
   * @param {KeyUsage[]} keyUsages - The allowed usages for the new key.
   * @returns {Promise<CryptoKeyPair>} A promise that resolves to the new key pair.
   * @function generateKey
   * @memberOf module:@decaf-ts/crypto
   */
  generateKey(
    algorithm: EcKeyGenParams | RsaHashedKeyGenParams,
    extractable: boolean,
    keyUsages: readonly KeyUsage[]
  ): Promise<CryptoKeyPair>;

  /**
   * @description Generates a new key or key pair.
   * @param {AesKeyGenParams | HmacKeyGenParams | Pbkdf2Params} algorithm - The algorithm to use for key generation.
   * @param {boolean} extractable - Whether the new key can be extracted.
   * @param {KeyUsage[]} keyUsages - The allowed usages for the new key.
   * @returns {Promise<CryptoKey>} A promise that resolves to the new key.
   * @function generateKey
   * @memberOf module:@decaf-ts/crypto
   */
  generateKey(
    algorithm: AesKeyGenParams | HmacKeyGenParams | Pbkdf2Params,
    extractable: boolean,
    keyUsages: readonly KeyUsage[]
  ): Promise<CryptoKey>;

  /**
   * @description Generates a new key or key pair.
   * @param {AlgorithmIdentifier} algorithm - The algorithm to use for key generation.
   * @param {boolean} extractable - Whether the new key can be extracted.
   * @param {KeyUsage[]} keyUsages - The allowed usages for the new key.
   * @returns {Promise<CryptoKey | CryptoKeyPair>} A promise that resolves to the new key or key pair.
   * @function generateKey
   * @memberOf module:@decaf-ts/crypto
   */
  generateKey(
    algorithm: AlgorithmIdentifier,
    extractable: boolean,
    keyUsages: KeyUsage[]
  ): Promise<CryptoKey | CryptoKeyPair>;

  /**
   * @description Generates a new key or key pair.
   * @param {"Ed25519"} algorithm - The algorithm to use for key generation.
   * @param {boolean} extractable - Whether the new key can be extracted.
   * @param {KeyUsage[]} keyUsages - The allowed usages for the new key.
   * @returns {Promise<CryptoKeyPair>} A promise that resolves to the new key pair.
   * @function generateKey
   * @memberOf module:@decaf-ts/crypto
   */
  generateKey(
    algorithm: "Ed25519",
    extractable: boolean,
    keyUsages: readonly ("sign" | "verify")[]
  ): Promise<CryptoKeyPair>;

  /**
   * @description Generates a new key or key pair.
   * @param {EcKeyGenParams | RsaHashedKeyGenParams} algorithm - The algorithm to use for key generation.
   * @param {boolean} extractable - Whether the new key can be extracted.
   * @param {KeyUsage[]} keyUsages - The allowed usages for the new key.
   * @returns {Promise<CryptoKeyPair>} A promise that resolves to the new key pair.
   * @function generateKey
   * @memberOf module:@decaf-ts/crypto
   */
  generateKey(
    algorithm: EcKeyGenParams | RsaHashedKeyGenParams,
    extractable: boolean,
    keyUsages: readonly KeyUsage[]
  ): Promise<CryptoKeyPair>;

  /**
   * @description Generates a new key or key pair.
   * @param {AesKeyGenParams | HmacKeyGenParams | Pbkdf2Params} algorithm - The algorithm to use for key generation.
   * @param {boolean} extractable - Whether the new key can be extracted.
   * @param {KeyUsage[]} keyUsages - The allowed usages for the new key.
   * @returns {Promise<CryptoKey>} A promise that resolves to the new key.
   * @function generateKey
   * @memberOf module:@decaf-ts/crypto
   */
  generateKey(
    algorithm: AesKeyGenParams | HmacKeyGenParams | Pbkdf2Params,
    extractable: boolean,
    keyUsages: readonly KeyUsage[]
  ): Promise<CryptoKey>;

  /**
   * @description Generates a new key or key pair.
   * @param {AlgorithmIdentifier} algorithm - The algorithm to use for key generation.
   * @param {boolean} extractable - Whether the new key can be extracted.
   * @param {KeyUsage[]} keyUsages - The allowed usages for the new key.
   * @returns {Promise<CryptoKey | CryptoKeyPair>} A promise that resolves to the new key or key pair.
   * @function generateKey
   * @memberOf module:@decaf-ts/crypto
   */
  generateKey(
    algorithm: AlgorithmIdentifier,
    extractable: boolean,
    keyUsages: Iterable<KeyUsage>
  ): Promise<CryptoKey | CryptoKeyPair>;

  /**
   * @description Imports a key.
   * @param {"jwk"} format - The format of the key to import.
   * @param {JsonWebKey} keyData - The key data in JWK format.
   * @param {AesKeyAlgorithm | AlgorithmIdentifier | EcKeyImportParams | HmacImportParams | RsaHashedImportParams} algorithm - The algorithm to use for the imported key.
   * @param {boolean} extractable - Whether the new key can be extracted.
   * @param {KeyUsage[]} keyUsages - The allowed usages for the new key.
   * @returns {Promise<CryptoKey>} A promise that resolves to the imported key.
   * @function importKey
   * @memberOf module:@decaf-ts/crypto
   */
  importKey(
    format: "jwk",
    keyData: JsonWebKey,
    algorithm:
      | AesKeyAlgorithm
      | AlgorithmIdentifier
      | EcKeyImportParams
      | HmacImportParams
      | RsaHashedImportParams,
    extractable: boolean,
    keyUsages: readonly KeyUsage[]
  ): Promise<CryptoKey>;

  /**
   * @description Imports a key.
   * @param {"raw" | "pkcs8" | "spki"} format - The format of the key to import.
   * @param {BufferSource} keyData - The key data.
   * @param {AesKeyAlgorithm | AlgorithmIdentifier | EcKeyImportParams | HmacImportParams | RsaHashedImportParams} algorithm - The algorithm to use for the imported key.
   * @param {boolean} extractable - Whether the new key can be extracted.
   * @param {KeyUsage[]} keyUsages - The allowed usages for the new key.
   * @returns {Promise<CryptoKey>} A promise that resolves to the imported key.
   * @function importKey
   * @memberOf module:@decaf-ts/crypto
   */
  importKey(
    format: "raw" | "pkcs8" | "spki",
    keyData: BufferSource,
    algorithm:
      | AesKeyAlgorithm
      | AlgorithmIdentifier
      | EcKeyImportParams
      | HmacImportParams
      | RsaHashedImportParams,
    extractable: boolean,
    keyUsages: KeyUsage[]
  ): Promise<CryptoKey>;

  /**
   * @description Imports a key.
   * @param {"jwk"} format - The format of the key to import.
   * @param {JsonWebKey} keyData - The key data in JWK format.
   * @param {AesKeyAlgorithm | AlgorithmIdentifier | EcKeyImportParams | HmacImportParams | RsaHashedImportParams} algorithm - The algorithm to use for the imported key.
   * @param {boolean} extractable - Whether the new key can be extracted.
   * @param {KeyUsage[]} keyUsages - The allowed usages for the new key.
   * @returns {Promise<CryptoKey>} A promise that resolves to the imported key.
   * @function importKey
   * @memberOf module:@decaf-ts/crypto
   */
  importKey(
    format: "jwk",
    keyData: JsonWebKey,
    algorithm:
      | AesKeyAlgorithm
      | AlgorithmIdentifier
      | EcKeyImportParams
      | HmacImportParams
      | RsaHashedImportParams,
    extractable: boolean,
    keyUsages: readonly KeyUsage[]
  ): Promise<CryptoKey>;

  /**
   * @description Imports a key.
   * @param {"raw" | "pkcs8" | "spki"} format - The format of the key to import.
   * @param {BufferSource} keyData - The key data.
   * @param {AesKeyAlgorithm | AlgorithmIdentifier | EcKeyImportParams | HmacImportParams | RsaHashedImportParams} algorithm - The algorithm to use for the imported key.
   * @param {boolean} extractable - Whether the new key can be extracted.
   * @param {KeyUsage[]} keyUsages - The allowed usages for the new key.
   * @returns {Promise<CryptoKey>} A promise that resolves to the imported key.
   * @function importKey
   * @memberOf module:@decaf-ts/crypto
   */
  importKey(
    format: "raw" | "pkcs8" | "spki",
    keyData: BufferSource,
    algorithm:
      | AesKeyAlgorithm
      | AlgorithmIdentifier
      | EcKeyImportParams
      | HmacImportParams
      | RsaHashedImportParams,
    extractable: boolean,
    keyUsages: Iterable<KeyUsage>
  ): Promise<CryptoKey>;

  /**
   * @description Signs data.
   * @param {EcdsaParams | AlgorithmIdentifier | RsaPssParams} algorithm - The algorithm to use for signing.
   * @param {CryptoKey} key - The key to use for signing.
   * @param {BufferSource} data - The data to sign.
   * @returns {Promise<ArrayBuffer>} A promise that resolves to the signature.
   * @function sign
   * @memberOf module:@decaf-ts/crypto
   */
  sign(
    algorithm: EcdsaParams | AlgorithmIdentifier | RsaPssParams,
    key: CryptoKey,
    data: BufferSource
  ): Promise<ArrayBuffer>;

  /**
   * @description Unwraps a key.
   * @param {KeyFormat} format - The format of the wrapped key.
   * @param {BufferSource} wrappedKey - The key to unwrap.
   * @param {CryptoKey} unwrappingKey - The key to use for unwrapping.
   * @param {AesCbcParams | AesCtrParams | AesGcmParams | AlgorithmIdentifier | RsaOaepParams} unwrapAlgorithm - The algorithm to use for unwrapping.
   * @param {AesKeyAlgorithm | AlgorithmIdentifier | EcKeyImportParams | HmacImportParams | RsaHashedImportParams} unwrappedKeyAlgorithm - The algorithm of the key to be unwrapped.
   * @param {boolean} extractable - Whether the unwrapped key can be extracted.
   * @param {KeyUsage[]} keyUsages - The allowed usages for the unwrapped key.
   * @returns {Promise<CryptoKey>} A promise that resolves to the unwrapped key.
   * @function unwrapKey
   * @memberOf module:@decaf-ts/crypto
   */
  unwrapKey(
    format: KeyFormat,
    wrappedKey: BufferSource,
    unwrappingKey: CryptoKey,
    unwrapAlgorithm:
      | AesCbcParams
      | AesCtrParams
      | AesGcmParams
      | AlgorithmIdentifier
      | RsaOaepParams,
    unwrappedKeyAlgorithm:
      | AesKeyAlgorithm
      | AlgorithmIdentifier
      | EcKeyImportParams
      | HmacImportParams
      | RsaHashedImportParams,
    extractable: boolean,
    keyUsages: KeyUsage[]
  ): Promise<CryptoKey>;

  /**
   * @description Unwraps a key.
   * @param {KeyFormat} format - The format of the wrapped key.
   * @param {BufferSource} wrappedKey - The key to unwrap.
   * @param {CryptoKey} unwrappingKey - The key to use for unwrapping.
   * @param {AesCbcParams | AesCtrParams | AesGcmParams | AlgorithmIdentifier | RsaOaepParams} unwrapAlgorithm - The algorithm to use for unwrapping.
   * @param {AesKeyAlgorithm | AlgorithmIdentifier | EcKeyImportParams | HmacImportParams | RsaHashedImportParams} unwrappedKeyAlgorithm - The algorithm of the key to be unwrapped.
   * @param {boolean} extractable - Whether the unwrapped key can be extracted.
   * @param {Iterable<KeyUsage>} keyUsages - The allowed usages for the unwrapped key.
   * @returns {Promise<CryptoKey>} A promise that resolves to the unwrapped key.
   * @function unwrapKey
   * @memberOf module:@decaf-ts/crypto
   */
  unwrapKey(
    format: KeyFormat,
    wrappedKey: BufferSource,
    unwrappingKey: CryptoKey,
    unwrapAlgorithm:
      | AesCbcParams
      | AesCtrParams
      | AesGcmParams
      | AlgorithmIdentifier
      | RsaOaepParams,
    unwrappedKeyAlgorithm:
      | AesKeyAlgorithm
      | AlgorithmIdentifier
      | EcKeyImportParams
      | HmacImportParams
      | RsaHashedImportParams,
    extractable: boolean,
    keyUsages: Iterable<KeyUsage>
  ): Promise<CryptoKey>;

  /**
   * @description Verifies a signature.
   * @param {EcdsaParams | AlgorithmIdentifier | RsaPssParams} algorithm - The algorithm to use for verification.
   * @param {CryptoKey} key - The key to use for verification.
   * @param {BufferSource} signature - The signature to verify.
   * @param {BufferSource} data - The data whose signature is to be verified.
   * @returns {Promise<boolean>} A promise that resolves to a boolean indicating whether the signature is valid.
   * @function verify
   * @memberOf module:@decaf-ts/crypto
   */
  verify(
    algorithm: EcdsaParams | AlgorithmIdentifier | RsaPssParams,
    key: CryptoKey,
    signature: BufferSource,
    data: BufferSource
  ): Promise<boolean>;

  /**
   * @description Wraps a key.
   * @param {KeyFormat} format - The format of the key to wrap.
   * @param {CryptoKey} key - The key to wrap.
   * @param {CryptoKey} wrappingKey - The key to use for wrapping.
   * @param {AesCbcParams | AesCtrParams | AesGcmParams | AlgorithmIdentifier | RsaOaepParams} wrapAlgorithm - The algorithm to use for wrapping.
   * @returns {Promise<ArrayBuffer>} A promise that resolves to the wrapped key.
   * @function wrapKey
   * @memberOf module:@decaf-ts/crypto
   */
  wrapKey(
    format: KeyFormat,
    key: CryptoKey,
    wrappingKey: CryptoKey,
    wrapAlgorithm:
      | AesCbcParams
      | AesCtrParams
      | AesGcmParams
      | AlgorithmIdentifier
      | RsaOaepParams
  ): Promise<ArrayBuffer>;
}
