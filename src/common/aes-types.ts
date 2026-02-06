import { Algorithm, BufferSource } from "./util-types";

/**
 * @description Represents the algorithm parameters for an AES key.
 * @interface AesKeyAlgorithm
 * @extends Algorithm
 * @property {number} length - The length of the key in bits.
 * @memberOf module:@decaf-ts/crypto
 */
export interface AesKeyAlgorithm extends Algorithm {
  length: number;
}

/**
 * @description Represents the algorithm parameters for generating an AES key.
 * @interface AesKeyGenParams
 * @extends Algorithm
 * @property {number} length - The length of the key in bits.
 * @memberOf module:@decaf-ts/crypto
 */
export interface AesKeyGenParams extends Algorithm {
  length: number;
}

/**
 * @description Represents the algorithm parameters for AES-CBC.
 * @interface AesCbcParams
 * @extends Algorithm
 * @property {BufferSource} iv - The initialization vector.
 * @memberOf module:@decaf-ts/crypto
 */
export interface AesCbcParams extends Algorithm {
  iv: BufferSource;
}

/**
 * @description Represents the algorithm parameters for AES-CTR.
 * @interface AesCtrParams
 * @extends Algorithm
 * @property {BufferSource} counter - The initial value of the counter block.
 * @property {number} length - The number of bits in the counter block that are used for the counter.
 * @memberOf module:@decaf-ts/crypto
 */
export interface AesCtrParams extends Algorithm {
  counter: BufferSource;
  length: number;
}

/**
 * @description Represents the algorithm parameters for AES-GCM.
 * @interface AesGcmParams
 * @extends Algorithm
 * @property {BufferSource} iv - The initialization vector.
 * @property {BufferSource} [additionalData] - Additional data that will be authenticated but not encrypted.
 * @property {number} [tagLength] - The desired length of the authentication tag in bits.
 * @memberOf module:@decaf-ts/crypto
 */
export interface AesGcmParams extends Algorithm {
  iv: BufferSource;
  additionalData?: BufferSource;
  tagLength?: number;
}

/**
 * @description Represents the algorithm parameters for deriving an AES key.
 * @interface AesDerivedKeyParams
 * @extends Algorithm
 * @property {number} length - The length of the derived key in bits.
 * @memberOf module:@decaf-ts/crypto
 */
export interface AesDerivedKeyParams extends Algorithm {
  length: number;
}
