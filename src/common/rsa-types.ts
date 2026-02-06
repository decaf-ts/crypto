import { Algorithm, AlgorithmIdentifier, BufferSource } from "./util-types";

/**
 * @description Represents the algorithm parameters for an RSA key.
 * @interface RsaKeyAlgorithm
 * @extends Algorithm
 * @property {number} modulusLength - The length of the RSA modulus in bits.
 * @property {Uint8Array} publicExponent - The public exponent of the RSA key.
 * @memberOf module:@decaf-ts/crypto
 */
export interface RsaKeyAlgorithm extends Algorithm {
  modulusLength: number;
  publicExponent: Uint8Array;
}

/**
 * @description Represents the algorithm parameters for a hashed RSA key.
 * @interface RsaHashedKeyAlgorithm
 * @extends RsaKeyAlgorithm
 * @property {AlgorithmIdentifier} hash - The hash algorithm to use.
 * @memberOf module:@decaf-ts/crypto
 */
export interface RsaHashedKeyAlgorithm extends RsaKeyAlgorithm {
  hash: AlgorithmIdentifier;
}

/**
 * @description Represents the algorithm parameters for generating a hashed RSA key.
 * @interface RsaHashedKeyGenParams
 * @extends RsaKeyAlgorithm
 * @property {AlgorithmIdentifier} hash - The hash algorithm to use.
 * @memberOf module:@decaf-ts/crypto
 */
export interface RsaHashedKeyGenParams extends RsaKeyAlgorithm {
  hash: AlgorithmIdentifier;
}

/**
 * @description Represents the algorithm parameters for importing a hashed RSA key.
 * @interface RsaHashedImportParams
 * @extends Algorithm
 * @property {AlgorithmIdentifier} hash - The hash algorithm to use.
 * @memberOf module:@decaf-ts/crypto
 */
export interface RsaHashedImportParams extends Algorithm {
  hash: AlgorithmIdentifier;
}

/**
 * @description Represents the algorithm parameters for RSA-OAEP.
 * @interface RsaOaepParams
 * @extends Algorithm
 * @property {BufferSource} [label] - An optional label to associate with the message.
 * @memberOf module:@decaf-ts/crypto
 */
export interface RsaOaepParams extends Algorithm {
  label?: BufferSource;
}

/**
 * @description Represents the algorithm parameters for RSA-PSS.
 * @interface RsaPssParams
 * @extends Algorithm
 * @property {number} saltLength - The length of the salt in bytes.
 * @memberOf module:@decaf-ts/crypto
 */
export interface RsaPssParams extends Algorithm {
  saltLength: number;
}
