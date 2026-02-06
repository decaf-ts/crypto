/**
 * @description Options for JSON Web Token (JWT) operations.
 * @summary
 * This type defines the configuration options used when signing or verifying JWTs.
 * @typedef {object} JwtOptions
 * @property {string} secret - The secret key used for signing and verifying the JWT.
 * @property {string} [expiry] - The expiration time for the JWT, e.g., "5m", "1h", "2d".
 * @memberOf module:@decaf-ts/crypto/jwt
 */
export type JwtOptions = {
  secret: string;
  expiry?: string;
};
