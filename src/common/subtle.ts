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

export interface SubtleCrypto {
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

  deriveBits(
    algorithm:
      | EcdhKeyDeriveParams
      | AlgorithmIdentifier
      | HkdfParams
      | Pbkdf2Params,
    baseKey: CryptoKey,
    length?: number
  ): Promise<ArrayBuffer>;

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

  digest(
    algorithm: AlgorithmIdentifier,
    data: BufferSource
  ): Promise<ArrayBuffer>;

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

  exportKey(format: "jwk", key: CryptoKey): Promise<JsonWebKey>;

  exportKey(
    format: "raw" | "pkcs8" | "spki",
    key: CryptoKey
  ): Promise<ArrayBuffer>;

  exportKey(
    format: KeyFormat,
    key: CryptoKey
  ): Promise<ArrayBuffer | JsonWebKey>;

  generateKey(
    algorithm: "Ed25519",
    extractable: boolean,
    keyUsages: readonly ("sign" | "verify")[]
  ): Promise<CryptoKeyPair>;

  generateKey(
    algorithm: EcKeyGenParams | RsaHashedKeyGenParams,
    extractable: boolean,
    keyUsages: readonly KeyUsage[]
  ): Promise<CryptoKeyPair>;

  generateKey(
    algorithm: AesKeyGenParams | HmacKeyGenParams | Pbkdf2Params,
    extractable: boolean,
    keyUsages: readonly KeyUsage[]
  ): Promise<CryptoKey>;

  generateKey(
    algorithm: AlgorithmIdentifier,
    extractable: boolean,
    keyUsages: KeyUsage[]
  ): Promise<CryptoKey | CryptoKeyPair>;

  generateKey(
    algorithm: "Ed25519",
    extractable: boolean,
    keyUsages: readonly ("sign" | "verify")[]
  ): Promise<CryptoKeyPair>;

  generateKey(
    algorithm: EcKeyGenParams | RsaHashedKeyGenParams,
    extractable: boolean,
    keyUsages: readonly KeyUsage[]
  ): Promise<CryptoKeyPair>;

  generateKey(
    algorithm: AesKeyGenParams | HmacKeyGenParams | Pbkdf2Params,
    extractable: boolean,
    keyUsages: readonly KeyUsage[]
  ): Promise<CryptoKey>;

  generateKey(
    algorithm: AlgorithmIdentifier,
    extractable: boolean,
    keyUsages: Iterable<KeyUsage>
  ): Promise<CryptoKey | CryptoKeyPair>;

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

  sign(
    algorithm: EcdsaParams | AlgorithmIdentifier | RsaPssParams,
    key: CryptoKey,
    data: BufferSource
  ): Promise<ArrayBuffer>;

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

  verify(
    algorithm: EcdsaParams | AlgorithmIdentifier | RsaPssParams,
    key: CryptoKey,
    signature: BufferSource,
    data: BufferSource
  ): Promise<boolean>;

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
