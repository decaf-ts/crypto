import { Algorithm, AlgorithmIdentifier, BufferSource } from "./util-types";

/**
 * @description Represents the algorithm parameters for PBKDF2.
 * @interface Pbkdf2Params
 * @extends Algorithm
 * @property {BufferSource} salt - The salt to use for the derivation.
 * @property {number} iterations - The number of iterations to use for the derivation.
 * @property {AlgorithmIdentifier} hash - The hash algorithm to use for the derivation.
 * @memberOf module:@decaf-ts/crypto
 */
export interface Pbkdf2Params extends Algorithm {
  salt: BufferSource;
  iterations: number;
  hash: AlgorithmIdentifier;
}

/**
 * @description Represents the algorithm parameters for HKDF.
 * @interface HkdfParams
 * @extends Algorithm
 * @property {AlgorithmIdentifier} hash - The hash algorithm to use.
 * @property {BufferSource} salt - The salt to use for the derivation.
 * @property {BufferSource} info - The application-specific information for the derivation.
 * @memberOf module:@decaf-ts/crypto
 */
export interface HkdfParams extends Algorithm {
  hash: AlgorithmIdentifier;
  salt: BufferSource;
  info: BufferSource;
}
