import { AuthorizationError } from "@decaf-ts/core";
import { InternalError } from "@decaf-ts/db-decorators";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { JwtOptions, JwtClaims } from "./types";

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function payloadOf(jwt: string): unknown | undefined {
  try {
    const body = jwt.split(".")[1] ?? "";
    if (!body) return undefined;
    return JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    return undefined;
  }
}

function secretKey(option: JwtOptions): Uint8Array {
  if (!option.secret) {
    throw new InternalError("Missing JWT secret");
  }
  return new TextEncoder().encode(option.secret);
}

function jwksFor(url: string) {
  let jwks = jwksCache.get(url);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(url));
    jwksCache.set(url, jwks);
  }
  return jwks;
}

export function decodeJwtPayload<OBJ extends object = object>(
  token: string
): OBJ | undefined {
  return payloadOf(token) as OBJ | undefined;
}

export function getTokenPayload<OBJ extends object = object>(
  token: string
): OBJ | null {
  return decodeJwtPayload<OBJ>(token) ?? null;
}

export function getUser(token: string): JwtClaims | undefined {
  const payload = getTokenPayload<JwtClaims & { iss?: string }>(token);
  if (!payload) return undefined;
  return {
    preferred_username: payload.preferred_username,
    email: payload.email,
    email_verified: payload.email_verified,
    name: payload.name,
    given_name: payload.given_name,
    family_name: payload.family_name,
  };
}

/**
 * @description Verifies a JSON Web Token (JWT) and returns its verified payload.
 * @summary
 * This is the core verification routine. It applies a three-tier strategy, in
 * order of precedence:
 * <ol>
 *   <li>When <code>option.verifyUrl</code> is set, verifies the token signature
 *       against a remote JWKS endpoint (via jose's <code>createRemoteJWKSet</code>).</li>
 *   <li>Otherwise, when <code>option.secret</code> is set, verifies the token
 *       signature using HS256 with the provided secret, honoring
 *       <code>option.clockToleranceSeconds</code> if present.</li>
 *   <li>Otherwise, when <code>option.allowDecodeOnly === true</code>, decodes the
 *       payload without verifying the signature. This is an explicit opt-in escape
 *       hatch. If none of the above apply, an <code>InternalError</code> is thrown
 *       because JWT verification is not configured.</li>
 * </ol>
 * @param {string} token - The JSON Web Token to verify.
 * @param {JwtOptions} option - Options controlling JWT verification: the JWKS URL, secret, clock tolerance, and decode-only escape hatch.
 * @returns {Promise<OBJ>} A promise that resolves to the verified JWT payload object.
 * @throws {AuthorizationError} If the token is invalid, malformed, or its signature cannot be verified.
 * @throws {InternalError} If no verification configuration is present and decode-only is not explicitly allowed.
 * @function verifyJwt
 * @memberOf module:@decaf-ts/crypto/jwt
 */
export async function verifyJwt<OBJ extends object = object>(
  token: string,
  option: JwtOptions
): Promise<OBJ> {
  if (option.verifyUrl) {
    try {
      const { payload } = await jwtVerify(token, jwksFor(option.verifyUrl), {
        clockTolerance: option.clockToleranceSeconds
          ? `${option.clockToleranceSeconds}s`
          : undefined,
      });
      return payload as unknown as OBJ;
    } catch (error) {
      throw new AuthorizationError(
        `Invalid token: ${(error as Error)?.message ?? String(error)}`
      );
    }
  }

  if (option.secret) {
    try {
      const { payload } = await jwtVerify(token, secretKey(option), {
        algorithms: ["HS256"],
        clockTolerance: option.clockToleranceSeconds
          ? `${option.clockToleranceSeconds}s`
          : undefined,
      });
      return payload as unknown as OBJ;
    } catch (error) {
      throw new AuthorizationError(
        `Invalid token: ${(error as Error)?.message ?? String(error)}`
      );
    }
  }

  if (option.allowDecodeOnly) {
    const payload = decodeJwtPayload<OBJ>(token);
    if (!payload) throw new AuthorizationError("Invalid token");
    return payload;
  }

  throw new InternalError(
    "JWT verification is not configured: set a secret or verifyUrl (or explicitly allow decode-only)"
  );
}

/**
 * @description Verifies a JSON Web Token (JWT).
 * @summary
 * Verifies a JWT using a three-tier strategy. When <code>option.verifyUrl</code> is
 * set, the token is verified against a remote JWKS endpoint. Otherwise, when
 * <code>option.secret</code> is set, the token is verified with HS256 honoring
 * <code>option.clockToleranceSeconds</code>. If neither is configured, the token is
 * decoded without verifying its signature <strong>only</strong> when
 * <code>option.allowDecodeOnly === true</code>; otherwise an <code>InternalError</code>
 * is thrown because JWT verification is not configured. This is a thin wrapper
 * around {@link module:@decaf-ts/crypto/jwt.verifyJwt|verifyJwt}.
 * @param {string} token - The JSON Web Token to verify.
 * @param {JwtOptions} option - Options controlling JWT verification, including the JWKS URL, secret, clock tolerance, and decode-only escape hatch.
 * @returns {Promise<OBJ>} A promise that resolves to the verified JWT payload object.
 * @throws {AuthorizationError} If the token is invalid, malformed, or its signature cannot be verified.
 * @throws {InternalError} If no verification configuration is present and decode-only is not explicitly allowed.
 * @function verify
 * @memberOf module:@decaf-ts/crypto/jwt
 */
export async function verify<OBJ extends object = object>(
  token: string,
  option: JwtOptions
): Promise<OBJ> {
  return verifyJwt<OBJ>(token, option);
}
