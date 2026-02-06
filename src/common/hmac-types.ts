import { Algorithm, AlgorithmIdentifier } from "./util-types";

/**
 * @description Represents the algorithm parameters for an HMAC key.
 * @interface HmacKeyAlgorithm
 * @extends Algorithm
 * @property {AlgorithmIdentifier} hash - The hash algorithm to use.
 * @property {number} length - The length of the key in bits.
 * @memberOf module:@decaf-ts/crypto
 */
export interface HmacKeyAlgorithm extends Algorithm {
  hash: AlgorithmIdentifier;
  length: number;
}

/**
 * @description Represents the algorithm parameters for importing an HMAC key.
 * @interface HmacImportParams
 * @extends Algorithm
 * @property {AlgorithmIdentifier} hash - The hash algorithm to use.
 * @property {number} [length] - The length of the key in bits.
 * @memberOf module:@decaf-ts/crypto
 */
export interface HmacImportParams extends Algorithm {
  hash: AlgorithmIdentifier;
  length?: number;
}

/**
 * @description Represents the algorithm parameters for generating an HMAC key.
 * @interface HmacKeyGenParams
 * @extends Algorithm
 * @property {AlgorithmIdentifier} hash - The hash algorithm to use.
 * @property {number} [length] - The length of the key in bits.
 * @memberOf module:@decaf-ts/crypto
 */
export interface HmacKeyGenParams extends Algorithm {
  hash: AlgorithmIdentifier;
  length?: number;
}
