/**
 * @module @decaf-ts/crypto
 * @description
 * This module provides a set of common types and interfaces for cryptographic operations within the decaf-ts ecosystem.
 * It serves as the main entry point for accessing shared cryptographic type definitions.
 * @summary
 * This module exports various type definitions for cryptographic algorithms and concepts, including:
 * - {@link module:@decaf-ts/crypto.AesCbcParams|AES-CBC}, {@link module:@decaf-ts/crypto.AesCtrParams|AES-CTR}, {@link module:@decaf-ts/crypto.AesGcmParams|AES-GCM} parameters.
 * - {@link module:@decaf-ts/crypto.HmacKeyGenParams|HMAC} parameters.
 * - {@link module:@decaf-ts/crypto.RsaHashedKeyGenParams|RSA} parameters.
 * - {@link module:@decaf-ts/crypto.EcKeyGenParams|Elliptic Curve} parameters.
 * - Utility types like {@link module:@decaf-ts/crypto.AlgorithmIdentifier|AlgorithmIdentifier}, {@link module:@decaf-ts/crypto.BufferSource|BufferSource}, and {@link module:@decaf-ts/crypto.KeyUsage|KeyUsage}.
 * - {@link module:@decaf-ts/crypto.Pbkdf2Params|PBKDF2} parameters.
 * - Core crypto types like {@link module:@decaf-ts/crypto.CryptoKey|CryptoKey}, {@link module:@decaf-ts/crypto.CryptoKeyPair|CryptoKeyPair}, and {@link module:@decaf-ts/crypto.JsonWebKey|JsonWebKey}.
 *
 * It also exports the package version.
 */
export * from "./common/aes-types";
export * from "./common/hmac-types";
export * from "./common/rsa-types";
export * from "./common/ec-types";
export * from "./common/util-types";
export * from "./common/pbkdf2-types";
export * from "./common/crypto-types";
export * from "./version";