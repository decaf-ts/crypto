/**
 * @description Represents a cryptographic algorithm.
 * @summary
 * The `Algorithm` interface is a base interface for representing a cryptographic algorithm.
 * @interface Algorithm
 * @property {string} name - The name of the algorithm.
 * @memberOf module:@decaf-ts/crypto
 */
export interface Algorithm {
  name: string;
}

/**
 * @description Represents an algorithm identifier.
 * @summary
 * The `AlgorithmIdentifier` type can be a string or an object that conforms to the `Algorithm` interface.
 * @typedef {string | Algorithm} AlgorithmIdentifier
 * @memberOf module:@decaf-ts/crypto
 */
export type AlgorithmIdentifier = string | Algorithm;

/**
 * @description Represents a buffer of binary data.
 * @summary
 * The `BufferSource` type is a union of `ArrayBuffer` and `ArrayBufferView`.
 * It's used to represent binary data in cryptographic operations.
 * @typedef {ArrayBuffer | ArrayBufferView} BufferSource
 * @memberOf module:@decaf-ts/crypto
 */
export type BufferSource = ArrayBuffer | ArrayBufferView;

/**
 * @description Represents the format of a cryptographic key.
 * @summary
 * The `KeyFormat` type is a string that can be one of "raw", "pkcs8", "spki", or "jwk".
 * @typedef {"raw" | "pkcs8" | "spki" | "jwk"} KeyFormat
 * @memberOf module:@decaf-ts/crypto
 */
export type KeyFormat = "raw" | "pkcs8" | "spki" | "jwk";

/**
 * @description Represents the type of a cryptographic key.
 * @summary
 * The `KeyType` type is a string that can be one of "public", "private", or "secret".
 * @typedef {"public" | "private" | "secret"} KeyType
 * @memberOf module:@decaf-ts/crypto
 */
export type KeyType = "public" | "private" | "secret";

/**
 * @description Represents the intended usage of a cryptographic key.
 * @summary
 * The `KeyUsage` type is a string that can be one of "encrypt", "decrypt", "sign", "verify", "deriveKey", "deriveBits", "wrapKey", or "unwrapKey".
 * @typedef {"encrypt" | "decrypt" | "sign" | "verify" | "deriveKey" | "deriveBits" | "wrapKey" | "unwrapKey"} KeyUsage
 * @memberOf module:@decaf-ts/crypto
 */
export type KeyUsage =
  | "encrypt"
  | "decrypt"
  | "sign"
  | "verify"
  | "deriveKey"
  | "deriveBits"
  | "wrapKey"
  | "unwrapKey";
