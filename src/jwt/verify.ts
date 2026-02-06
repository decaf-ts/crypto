import { JwtOptions } from "./types";
import { jwtVerify } from "jose";

/**
 * @description Verifies a JSON Web Token (JWT).
 * @summary
 * This function takes a JWT string and JWT options (including the secret),
 * then verifies the token's signature and integrity using the HS256 algorithm.
 * @template OBJ - The expected type of the JWT payload.
 * @param {string} token - The JWT string to verify.
 * @param {JwtOptions} option - Options for verifying the JWT, including the secret.
 * @returns {Promise<OBJ>} A promise that resolves to the decoded JWT payload as the specified object type.
 * @throws {Error} If the JWT is invalid (e.g., signature mismatch, expired).
 * @function verify
 * @memberOf module:@decaf-ts/crypto/jwt
 *
 * @mermaid
 * sequenceDiagram
 *   participant Client
 *   participant VerifyFunction as verify()
 *   participant JoseLib as jose.jwtVerify
 *   participant TextEncoder
 *
 *   Client->>VerifyFunction: Call verify(token, options)
 *   VerifyFunction->>TextEncoder: Encode secret
 *   TextEncoder-->>VerifyFunction: KeyMaterial
 *   VerifyFunction->>JoseLib: jwtVerify(token, KeyMaterial)
 *   JoseLib-->>VerifyFunction: DecodedPayload
 *   VerifyFunction-->>Client: Returns DecodedPayload
 */
export async function verify<OBJ extends object = object>(
  token: string,
  option: JwtOptions
): Promise<OBJ> {
  const key = new TextEncoder().encode(option.secret);
  const { payload } = await jwtVerify(token, key, {
    algorithms: ["HS256"],
  });
  return payload as unknown as OBJ;
}
