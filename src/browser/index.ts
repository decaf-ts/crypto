/**
 * @module @decaf-ts/crypto/browser
 * @description
 * This module provides the browser-specific implementations of cryptographic functionalities.
 * @summary
 * This module exports the browser-specific implementations of the {@link module:@decaf-ts/crypto/browser.Subtle|SubtleCrypto} interface and the {@link module:@decaf-ts/crypto/browser.Crypto|Crypto} object. It ensures that the cryptographic operations are performed using the native Web Crypto API available in modern browsers.
 */
export * from "./Subtle";
export * from "./Crypto";
export * from "../version";
