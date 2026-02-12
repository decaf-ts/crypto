/**
 * @module @decaf-ts/crypto/common
 * @description
 * This module serves as a central hub for common cryptographic types and interfaces used across the `@decaf-ts/crypto` library.
 * @summary
 * This module re-exports a comprehensive set of type definitions for various cryptographic algorithms and concepts, ensuring a consistent API for both browser and Node.js environments. Key exports include types for AES, HMAC, RSA, Elliptic Curve, PBKDF2, and core cryptographic structures like {@link module:@decaf-ts/crypto.CryptoKey|CryptoKey}. It also exports the package {@link module:@decaf-ts/crypto.VERSION|VERSION}.
 */
export * from "./aes-types";
export * from "./hmac-types";
export * from "./rsa-types";
export * from "./ec-types";
export * from "./util-types";

export * from "./pbkdf2-types";
export * from "./crypto-types";
export * from "../version";
