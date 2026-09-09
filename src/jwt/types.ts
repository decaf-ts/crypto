/**
 * @description Options for JSON Web Token (JWT) operations.
 * @summary
 * This type defines the configuration options used when signing or verifying JWTs.
 * @typedef {object} JwtOptions
 * @property {string} [secret] - The secret key used for signing and verifying the JWT with HS256.
 * @property {string} [expiry] - The expiration time for the JWT, e.g., "5m", "1h", "2d".
 * @property {string} [verifyUrl] - The URL of a remote JWKS endpoint used to verify the JWT signature via asymmetric keys.
 * @property {number} [clockToleranceSeconds] - The clock tolerance, in seconds, used when verifying the token's time-based claims.
 * @property {boolean} [allowDecodeOnly] - Explicit opt-in escape hatch that decodes the JWT without verifying its signature. Never set by env parsing; it is code-level only and triggers a startup security warning when enabled.
 * @memberOf module:@decaf-ts/crypto/jwt
 */
export type JwtOptions = {
  secret?: string;
  expiry?: string;
  verifyUrl?: string;
  clockToleranceSeconds?: number;
  allowDecodeOnly?: boolean;
};

export interface JwtClaims {
  preferred_username?: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
}
