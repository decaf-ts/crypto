/**
 * @module @decaf-ts/crypto/jwt
 * @description
 * This module provides utilities for JSON Web Token (JWT) operations, including signing and verification.
 * @summary
 * This module exports functions for:
 * - {@link module:@decaf-ts/crypto/jwt.sign|Signing} JWTs.
 * - {@link module:@decaf-ts/crypto/jwt.verify|Verifying} JWTs.
 *
 * It also re-exports the package version.
 */
export * from "./sign";
export * from "./verify";
export * from "../version";