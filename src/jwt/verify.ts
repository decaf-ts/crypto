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
      });
      return payload as unknown as OBJ;
    } catch (error) {
      throw new AuthorizationError(
        `Invalid token: ${(error as Error)?.message ?? String(error)}`
      );
    }
  }

  const payload = decodeJwtPayload<OBJ>(token);
  if (!payload) throw new AuthorizationError("Invalid token");
  return payload;
}

/**
 * @description Verifies a JSON Web Token (JWT).
 * @summary Verifies using a configured JWKS endpoint when provided, otherwise falls back
 * to symmetric HS256 verification or decode-only mode when no verification config exists.
 */
export async function verify<OBJ extends object = object>(
  token: string,
  option: JwtOptions
): Promise<OBJ> {
  return verifyJwt<OBJ>(token, option);
}
