import {
  Algorithm,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  AlgorithmIdentifier,
  KeyType,
  KeyUsage,
} from "./util-types";

/**
 * @description Represents a cryptographic key.
 * @summary
 * The `CryptoKey` interface represents a cryptographic key obtained from one of the SubtleCrypto
 * operations (generateKey, deriveKey, importKey).
 * @interface CryptoKey
 * @property {KeyType} type - The type of key: "public", "private", or "secret".
 * @property {boolean} extractable - Whether the key can be extracted from the CryptoKey object.
 * @property {Algorithm} algorithm - The algorithm for which the key can be used.
 * @property {KeyUsage[]} usages - The operations for which the key can be used.
 * @memberOf module:@decaf-ts/crypto
 */
export interface CryptoKey {
  readonly type: KeyType;
  readonly extractable: boolean;
  readonly algorithm: Algorithm;
  readonly usages: readonly KeyUsage[];
}

/**
 * @description Represents a pair of cryptographic keys.
 * @summary
 * The `CryptoKeyPair` interface represents a key pair for an asymmetric cryptography algorithm,
 * also known as a public-key algorithm.
 * @interface CryptoKeyPair
 * @property {CryptoKey} publicKey - The public key.
 * @property {CryptoKey} privateKey - The private key.
 * @memberOf module:@decaf-ts/crypto
 */
export interface CryptoKeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

/**
 * @description Represents a cryptographic key in JSON Web Key format.
 * @summary
 * The `JsonWebKey` interface represents a key in the JSON Web Key (JWK) format.
 * This format is used to represent cryptographic keys as JSON objects.
 * @interface JsonWebKey
 * @property {string} [kty] - The key type (e.g., "RSA", "EC", "oct").
 * @property {string} [use] - The intended use of the public key (e.g., "sig", "enc").
 * @property {string[]} [key_ops] - The operations for which the key is intended to be used.
 * @property {string} [alg] - The algorithm intended for use with the key.
 * @property {string} [n] - The modulus for an RSA public key.
 * @property {string} [e] - The exponent for an RSA public key.
 * @property {string} [d] - The private exponent for an RSA private key.
 * @property {string} [p] - The first prime factor for an RSA private key.
 * @property {string} [q] - The second prime factor for an RSA private key.
 * @property {string} [dp] - The first factor CRT exponent for an RSA private key.
 * @property {string} [dq] - The second factor CRT exponent for an RSA private key.
 * @property {string} [qi] - The first CRT coefficient for an RSA private key.
 * @property {string} [crv] - The curve for an EC key.
 * @property {string} [x] - The x-coordinate for the EC point.
 * @property {string} [y] - The y-coordinate for the EC point.
 * @property {string} [k] - The value of the symmetric key.
 * @property {boolean} [ext] - Whether the key is extractable.
 * @memberOf module:@decaf-ts/crypto
 */
export interface JsonWebKey {
  kty?: string;
  use?: string;
  key_ops?: string[];
  alg?: string;

  // RSA
  n?: string;
  e?: string;
  d?: string;
  p?: string;
  q?: string;
  dp?: string;
  dq?: string;
  qi?: string;

  // EC
  crv?: string;
  x?: string;
  y?: string;

  // Symmetric
  k?: string;

  ext?: boolean;
}
