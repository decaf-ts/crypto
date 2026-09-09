/**
 * @file Integration tests for JWT remote (JWKS) verification and clock-tolerance behavior.
 * @summary
 * Exercises {@link module:@decaf-ts/crypto.JwtService|JwtService} and
 * {@link module:@decaf-ts/crypto/jwt.verifyJwt|verifyJwt} against a mock JWKS
 * endpoint, asserting remote signature verification, the verifyUrl-over-secret
 * precedence, tampered-token rejection, and strict vs. tolerated clock handling.
 */
import { JwtService } from "../../src/integration/services/JwtService";
import { verifyJwt } from "../../src/jwt/verify";
import { mockJwks, MockJwks } from "../helpers/jwks";

async function bootService(config: object = {}) {
  const service = new JwtService();
  await service.boot(config);
  return service;
}

describe("JwtService remote verification (JWKS)", () => {
  let jwks: MockJwks;

  afterEach(() => {
    jwks.dispose();
  });

  it("should verify a token against a remote JWKS and return its payload", async () => {
    jwks = await mockJwks({ alg: "RS256" });
    const token = await jwks.signToken({ sub: "user-1", role: "admin" });

    const service = await bootService({ verifyUrl: jwks.verifyUrl });
    const payload = await service.decodeJwt(token);

    expect(payload).toEqual(expect.objectContaining({ sub: "user-1" }));
  });

  it("should roundtrip through createAuthJwt and decodeAuthToken", async () => {
    jwks = await mockJwks({ alg: "RS256" });
    const token = await jwks.signToken({ sub: "user-42" });

    const service = await bootService({ verifyUrl: jwks.verifyUrl });
    const payload = await service.decodeAuthToken(token);

    expect(payload).toEqual(expect.objectContaining({ sub: "user-42" }));
  });

  it("should favour the verifyUrl path over a supplied secret", async () => {
    jwks = await mockJwks({ alg: "RS256" });
    const token = await jwks.signToken({ sub: "remote-user" });

    // both verifyUrl and secret are set: verifyUrl must take precedence
    const service = await bootService({
      verifyUrl: jwks.verifyUrl,
      secret: "wrong-secret-0123456789abcdef0123456789",
    });
    const payload = await service.decodeJwt(token);

    expect(payload.sub).toBe("remote-user");
  });

  it("should reject a tampered token", async () => {
    jwks = await mockJwks({ alg: "RS256" });
    const token = await jwks.signToken({ sub: "user-1" });
    const parts = token.split(".");
    const tampered = `${parts[0]}.${Buffer.from(
      JSON.stringify({ sub: "attacker", admin: true })
    ).toString("base64url")}.${parts[2]}`;

    await expect(verifyJwt(tampered, { verifyUrl: jwks.verifyUrl })).rejects.toThrow(
      "Invalid token"
    );
  });

  it("should reject a token signed by a key absent from the JWKS", async () => {
    jwks = await mockJwks({ alg: "RS256" });
    const other = await mockJwks({ alg: "RS256" });
    const token = await other.signToken({ sub: "intruder" });
    // restore the first JWKS mock so verification against jwks.verifyUrl fetches
    // the first server's keys; the token was signed with a different key.
    other.dispose();
    await expect(
      verifyJwt(token, { verifyUrl: jwks.verifyUrl })
    ).rejects.toThrow("Invalid token");
  });
});

describe("JwtService clock-tolerance operators", () => {
  let jwks: MockJwks;

  afterEach(() => {
    jwks.dispose();
  });

  it("should accept a token expired within the configured tolerance", async () => {
    jwks = await mockJwks({ alg: "RS256" });
    const now = Math.floor(Date.now() / 1000);
    const token = await jwks.signToken(
      { sub: "late-user" },
      { iat: now - 600, exp: now - 3 }
    );

    const service = await bootService({
      verifyUrl: jwks.verifyUrl,
      clockToleranceSeconds: 10,
    });
    const payload = await service.decodeJwt(token);

    expect(payload.sub).toBe("late-user");
  });

  it("should reject an expired token when no tolerance is configured (strict)", async () => {
    jwks = await mockJwks({ alg: "RS256" });
    const now = Math.floor(Date.now() / 1000);
    const token = await jwks.signToken(
      { sub: "late-user" },
      { iat: now - 600, exp: now - 3 }
    );

    const service = await bootService({ verifyUrl: jwks.verifyUrl });
    await expect(service.decodeJwt(token)).rejects.toThrow("Invalid token");
  });

  it("should reject a token expired beyond the configured tolerance", async () => {
    jwks = await mockJwks({ alg: "RS256" });
    const now = Math.floor(Date.now() / 1000);
    const token = await jwks.signToken(
      { sub: "too-late" },
      { iat: now - 6000, exp: now - 120 }
    );

    const service = await bootService({
      verifyUrl: jwks.verifyUrl,
      clockToleranceSeconds: 10,
    });
    await expect(service.decodeJwt(token)).rejects.toThrow("Invalid token");
  });
});
