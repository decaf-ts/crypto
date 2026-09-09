/**
 * @file Test helper for standing up a mock JWKS endpoint.
 * @summary
 * Stubs the global <code>fetch</code> used by jose's <code>createRemoteJWKSet</code>
 * to serve a generated key set, providing a <code>verifyUrl</code> and a signing
 * function so JWT verification tests can run against a remote JWKS without a real
 * identity provider. Each call produces a unique URL to avoid module-level cache
 * collisions across tests.
 */
import { generateKeyPair, exportJWK, SignJWT } from "jose";

export type JwksSignOptions = {
  iat?: number;
  exp?: number;
  expiry?: string;
  notBefore?: number;
};

export type MockJwks = {
  verifyUrl: string;
  kid: string;
  alg: string;
  signToken: (claims: object, opts?: JwksSignOptions) => Promise<string>;
  dispose: () => void;
};

/**
 * Sets up a mock JWKS endpoint by stubbing the global `fetch` used by jose's
 * `createRemoteJWKSet`. The returned `verifyUrl` points at a unique URL so the
 * module-level jwks cache never collides across tests.
 */
export async function mockJwks(opts?: { alg?: "RS256" | "ES256" }): Promise<MockJwks> {
  const alg = opts?.alg ?? "RS256";
  const { publicKey, privateKey } = await generateKeyPair(alg, {
    extractable: true,
  });
  const jwk = await exportJWK(publicKey);
  const kid = "mock-kid-1";
  jwk.kid = kid;
  jwk.use = "sig";
  jwk.alg = alg;
  const jwks = { keys: [jwk] };
  const verifyUrl = `https://mock-jwks.test/${crypto.randomUUID()}/.well-known/jwks.json`;

  const originalFetch = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (url === verifyUrl) {
      return new Response(JSON.stringify(jwks), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }
    return new Response(JSON.stringify({ error: "not found" }), { status: 404 });
  }) as typeof fetch;

  const signToken = async (claims: object, opts?: JwksSignOptions) => {
    let token = new SignJWT(claims).setProtectedHeader({ alg, typ: "JWT", kid });
    token =
      opts?.iat !== undefined ? token.setIssuedAt(opts.iat) : token.setIssuedAt();
    if (opts?.exp !== undefined) {
      token = token.setExpirationTime(opts.exp);
    } else if (opts?.expiry !== undefined) {
      token = token.setExpirationTime(opts.expiry);
    } else {
      token = token.setExpirationTime("5m");
    }
    if (opts?.notBefore !== undefined) {
      token = token.setNotBefore(opts.notBefore);
    }
    return await token.sign(privateKey);
  };

  return {
    verifyUrl,
    kid,
    alg,
    signToken,
    dispose() {
      globalThis.fetch = originalFetch;
    },
  };
}
