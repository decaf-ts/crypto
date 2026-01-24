import {
  AesCbcParams,
  AesCtrParams,
  AesDerivedKeyParams,
  AesGcmParams,
  AesKeyAlgorithm,
  AesKeyGenParams,
} from "./aes-types";
import {
  RsaHashedImportParams,
  RsaHashedKeyGenParams,
  RsaOaepParams,
  RsaPssParams,
} from "./rsa-types";
import { SubtleCrypto } from "./subtle";
import {
  AlgorithmIdentifier,
  BufferSource,
  KeyFormat,
  KeyUsage,
} from "./util-types";
import { CryptoKey, CryptoKeyPair, JsonWebKey } from "./crypto-types";
import { HkdfParams, Pbkdf2Params } from "./pbkdf2-types";
import {
  EcdhKeyDeriveParams,
  EcdsaParams,
  EcKeyGenParams,
  EcKeyImportParams,
} from "./ec-types";
import { HmacImportParams, HmacKeyGenParams } from "./hmac-types";

export class Subtle implements SubtleCrypto {
  constructor(protected subtle: SubtleCrypto) {}

  decrypt(
    algorithm:
      | AesCbcParams
      | AesCtrParams
      | AesGcmParams
      | AlgorithmIdentifier
      | RsaOaepParams,
    key: CryptoKey,
    data: BufferSource
  ): Promise<ArrayBuffer> {
    return this.subtle.decrypt(algorithm, key, data);
  }

  deriveBits(
    algorithm:
      | EcdhKeyDeriveParams
      | AlgorithmIdentifier
      | HkdfParams
      | Pbkdf2Params,
    baseKey: CryptoKey,
    length?: number
  ): Promise<ArrayBuffer> {
    return this.subtle.deriveBits(algorithm, baseKey, length);
  }

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
    keyUsages: KeyUsage[] | Iterable<KeyUsage>
  ): Promise<CryptoKey> {
    return this.subtle.deriveKey(
      algorithm,
      baseKey,
      derivedKeyType,
      extractable,
      keyUsages
    );
  }

  digest(
    algorithm: AlgorithmIdentifier,
    data: BufferSource
  ): Promise<ArrayBuffer> {
    return this.subtle.digest(algorithm, data);
  }

  encrypt(
    algorithm:
      | AesCbcParams
      | AesCtrParams
      | AesGcmParams
      | AlgorithmIdentifier
      | RsaOaepParams,
    key: CryptoKey,
    data: BufferSource
  ): Promise<ArrayBuffer> {
    return this.subtle.encrypt(algorithm, key, data);
  }

  exportKey(format: "jwk", key: CryptoKey): Promise<JsonWebKey>;
  exportKey(
    format: "raw" | "pkcs8" | "spki",
    key: CryptoKey
  ): Promise<ArrayBuffer>;
  exportKey(
    format: KeyFormat,
    key: CryptoKey
  ): Promise<ArrayBuffer | JsonWebKey>;
  exportKey(
    format: "jwk" | "raw" | "pkcs8" | "spki" | KeyFormat,
    key: CryptoKey
  ):
    | Promise<JsonWebKey>
    | Promise<ArrayBuffer>
    | Promise<ArrayBuffer | JsonWebKey> {
    return this.subtle.exportKey(format, key);
  }

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
    algorithm: AlgorithmIdentifier,
    extractable: boolean,
    keyUsages: Iterable<KeyUsage>
  ): Promise<CryptoKey | CryptoKeyPair>;
  generateKey(
    algorithm:
      | "Ed25519"
      | EcKeyGenParams
      | RsaHashedKeyGenParams
      | AesKeyGenParams
      | HmacKeyGenParams
      | Pbkdf2Params
      | AlgorithmIdentifier
      | "Ed25519",
    extractable: boolean,
    keyUsages:
      | readonly ("sign" | "verify")[]
      | readonly KeyUsage[]
      | KeyUsage[]
      | Iterable<KeyUsage>
  ):
    | Promise<CryptoKeyPair>
    | Promise<CryptoKey>
    | Promise<CryptoKey | CryptoKeyPair> {
    return this.subtle.generateKey(algorithm, extractable, keyUsages);
  }

  importKey(
    format: "jwk",
    // keyData: JsonWebKey,
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
  importKey(
    format: "jwk" | "raw" | "pkcs8" | "spki" | "jwk" | "raw" | "pkcs8" | "spki",
    keyData: JsonWebKey | BufferSource,
    algorithm:
      | AesKeyAlgorithm
      | AlgorithmIdentifier
      | EcKeyImportParams
      | HmacImportParams
      | RsaHashedImportParams,
    extractable: boolean,
    keyUsages: readonly KeyUsage[] | KeyUsage[] | Iterable<KeyUsage>
  ): Promise<CryptoKey> {
    return this.subtle.importKey(
      format,
      keyData,
      algorithm,
      extractable,
      keyUsages
    );
  }

  sign(
    algorithm: EcdsaParams | AlgorithmIdentifier | RsaPssParams,
    key: CryptoKey,
    data: BufferSource
  ): Promise<ArrayBuffer> {
    return this.subtle.sign(algorithm, key, data);
  }

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
    keyUsages: KeyUsage[] | Iterable<KeyUsage>
  ): Promise<CryptoKey> {
    return this.subtle.unwrapKey(
      format,
      wrappedKey,
      unwrappingKey,
      unwrapAlgorithm,
      unwrappedKeyAlgorithm,
      extractable,
      keyUsages
    );
  }

  verify(
    algorithm: EcdsaParams | AlgorithmIdentifier | RsaPssParams,
    key: CryptoKey,
    signature: BufferSource,
    data: BufferSource
  ): Promise<boolean> {
    return this.subtle.verify(algorithm, key, signature, data);
  }

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
  ): Promise<ArrayBuffer> {
    return this.subtle.wrapKey(format, key, wrappingKey, wrapAlgorithm);
  }
}
