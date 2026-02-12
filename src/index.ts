/**
 * @module @decaf-ts/crypto
 * @description
 * This module provides a unified API for cryptographic operations in both Node.js and browser environments.
 * It serves as the main entry point for the `@decaf-ts/crypto` library, exporting common types, interfaces, and utilities.
 * @summary
 * The `@decaf-ts/crypto` module exposes a range of cryptographic functionalities, including:
 * - A comprehensive set of type definitions for various cryptographic algorithms such as AES, HMAC, RSA, and Elliptic Curve.
 * - Core cryptographic types like {@link module:@decaf-ts/crypto.CryptoKey|CryptoKey}, {@link module:@decaf-ts/crypto.CryptoKeyPair|CryptoKeyPair}, and {@link module:@decaf-ts/crypto.JsonWebKey|JsonWebKey}.
 * - The package {@link module:@decaf-ts/crypto.VERSION|VERSION} and {@link module:@decaf-ts/crypto.PACKAGE_NAME|PACKAGE_NAME}.
 *
 * This module is designed to provide a consistent and environment-agnostic way to perform cryptographic operations within the decaf-ts ecosystem.
 */
export * from "./common/aes-types";
export * from "./common/hmac-types";
export * from "./common/rsa-types";
export * from "./common/ec-types";
export * from "./common/util-types";
export * from "./common/pbkdf2-types";
export * from "./common/crypto-types";
export * from "./version";
