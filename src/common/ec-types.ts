import { Algorithm, AlgorithmIdentifier } from "./util-types";
import { CryptoKey } from "jose";

/**
 * @description Represents the algorithm parameters for an EC key.
 * @interface EcKeyAlgorithm
 * @extends Algorithm
 * @property {string} namedCurve - The name of the elliptic curve.
 * @memberOf module:@decaf-ts/crypto
 */
export interface EcKeyAlgorithm extends Algorithm {
  namedCurve: string;
}

/**
 * @description Represents the algorithm parameters for generating an EC key.
 * @interface EcKeyGenParams
 * @extends Algorithm
 * @property {string} namedCurve - The name of the elliptic curve.
 * @memberOf module:@decaf-ts/crypto
 */
export interface EcKeyGenParams extends Algorithm {
  namedCurve: string;
}

/**
 * @description Represents the algorithm parameters for importing an EC key.
 * @interface EcKeyImportParams
 * @extends Algorithm
 * @property {string} namedCurve - The name of the elliptic curve.
 * @memberOf module:@decaf-ts/crypto
 */
export interface EcKeyImportParams extends Algorithm {
  namedCurve: string;
}

/**
 * @description Represents the algorithm parameters for ECDSA.
 * @interface EcdsaParams
 * @extends Algorithm
 * @property {AlgorithmIdentifier} hash - The hash algorithm to use.
 * @memberOf module:@decaf-ts/crypto
 */
export interface EcdsaParams extends Algorithm {
  hash: AlgorithmIdentifier;
}

/**
 * @description Represents the algorithm parameters for ECDH key derivation.
 * @interface EcdhKeyDeriveParams
 * @extends Algorithm
 * @property {CryptoKey} public - The public key of the other party.
 * @memberOf module:@decaf-ts/crypto
 */
export interface EcdhKeyDeriveParams extends Algorithm {
  public: CryptoKey;
}

/**
 * @description Represents the name of an elliptic curve.
 * @typedef {"P-256" | "P-384" | "P-521" | "X25519" | "Ed25519"} NamedCurve
 * @memberOf module:@decaf-ts/crypto
 */
export type NamedCurve = "P-256" | "P-384" | "P-521" | "X25519" | "Ed25519";
