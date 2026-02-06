import { SignJWT } from "jose";
import { JwtOptions } from "./types";

/**
 * @description Signs a JSON Web Token (JWT).
 * @summary
 * This function takes a payload object and JWT options, then signs the JWT using
 * the HS256 algorithm and a provided secret. It automatically sets the protected
 * header, issued at time, and expiration time.
 * @param {object} obj - The payload object to be included in the JWT.
 * @param {JwtOptions} option - Options for signing the JWT, including the secret and optional expiration time.
 * @returns {Promise<string>} A promise that resolves to the signed JWT string.
 * @function sign
 * @memberOf module:@decaf-ts/crypto/jwt
 *
 * @mermaid
 * sequenceDiagram
 *   participant Client
 *   participant SignFunction as sign()
 *   participant JoseLib as jose.SignJWT
 *   participant TextEncoder
 *
 *   Client->>SignFunction: Call sign(payload, options)
 *   SignFunction->>TextEncoder: Encode secret
 *   TextEncoder-->>SignFunction: KeyMaterial
 *   SignFunction->>JoseLib: new SignJWT(payload)
 *   JoseLib->>JoseLib: setProtectedHeader({ alg: "HS256", typ: "JWT" })
 *   JoseLib->>JoseLib: setIssuedAt()
 *   JoseLib->>JoseLib: setExpirationTime(options.expiry)
 *   JoseLib->>JoseLib: sign(KeyMaterial)
 *   JoseLib-->>SignFunction: SignedJWT
 *   SignFunction-->>Client: Returns SignedJWT
 */
export async function sign(obj: object, option: JwtOptions) {
  const key = new TextEncoder().encode(option.secret);
  // Add standard claims as needed (exp, iat, iss, aud, etc.)
  return await new SignJWT({ ...obj })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuedAt()
    .setExpirationTime(option.expiry || "5m")
    .sign(key);
}
