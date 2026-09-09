/**
 * @file Unit tests for the JWT service and verification fail-closed behavior.
 * @summary
 * Covers {@link module:@decaf-ts/crypto.JwtService|JwtService} header parsing,
 * decode helpers, env-driven initialization, default HS256 algorithm pinning,
 * sign/verify roundtrips, error handling, and the fail-closed guarantee of
 * {@link module:@decaf-ts/crypto/jwt.verifyJwt|verifyJwt}: it refuses to decode
 * without verification unless <code>allowDecodeOnly === true</code>.
 */
import { JwtService } from "../../src/integration/services/JwtService";
import { sign } from "../../src/jwt/sign";
import { verifyJwt } from "../../src/jwt/verify";
import { InternalError } from "@decaf-ts/db-decorators";
import { Logging } from "@decaf-ts/logging";
import { SignJWT } from "jose";

const ENV_SECRET = "JWT__SECRET";
const ENV_EXPIRY = "JWT__EXPIRY";
const ENV_VERIFY_URL = "JWT__VERIFY_URL";
const ENV_CLOCK_TOLERANCE = "JWT__CLOCK_TOLERANCE_SECONDS";

const SECRET = "unit-test-jwt-secret-that-is-at-least-32-bytes!";

function headerOf(token: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString());
}

function payloadOf(token: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString());
}

async function bootService(config: object = {}) {
  const service = new JwtService();
  await service.boot(config);
  return service;
}

describe("JwtService", () => {
  let svc: JwtService;

  beforeEach(() => {
    svc = new JwtService();
  });

  afterEach(() => {
    delete process.env[ENV_SECRET];
    delete process.env[ENV_EXPIRY];
    delete process.env[ENV_VERIFY_URL];
    delete process.env[ENV_CLOCK_TOLERANCE];
  });

  describe("fromHeader", () => {
    it("should extract the token from a Bearer authorization header", () => {
      expect(svc.fromHeader({ authorization: "Bearer abc.def.ghi" })).toBe(
        "abc.def.ghi"
      );
    });

    it("should return undefined for a non-Bearer scheme", () => {
      expect(
        svc.fromHeader({ authorization: "Basic dXNlcjpwYXNz" })
      ).toBeUndefined();
    });

    it("should return undefined when the header is missing", () => {
      expect(svc.fromHeader({})).toBeUndefined();
    });

    it("should return undefined when the header has no scheme", () => {
      expect(svc.fromHeader({ authorization: "abc.def.ghi" })).toBeUndefined();
    });
  });

  describe("decode helpers", () => {
    let token: string;

    beforeAll(async () => {
      const service = await bootService({ secret: SECRET, expiry: "1h" });
      const { access_token } = await service.createAuthJwt({
        sub: "user-1",
        preferred_username: "alice",
        email: "alice@example.test",
        email_verified: true,
        name: "Alice",
        given_name: "Alice",
        family_name: "Example",
        unknown: "dropped",
      });
      token = access_token;
    });

    it("should decode the payload without verification", () => {
      const payload = svc.decodePayload(token);
      expect(payload).toEqual(
        expect.objectContaining({ sub: "user-1", preferred_username: "alice" })
      );
    });

    it("should return null from getTokenPayload for an invalid token", () => {
      expect(svc.getTokenPayload("not-a-jwt")).toBeNull();
    });

    it("should return the payload from getTokenPayload", () => {
      const payload = svc.getTokenPayload(token);
      expect(payload).toEqual(expect.objectContaining({ sub: "user-1" }));
    });

    it("should extract only the known user claims", () => {
      const user = svc.getUser(token);
      expect(user).toEqual({
        preferred_username: "alice",
        email: "alice@example.test",
        email_verified: true,
        name: "Alice",
        given_name: "Alice",
        family_name: "Example",
      });
      expect(user).not.toHaveProperty("unknown");
    });
  });

  describe("environment parsing (initialize)", () => {
    it("should read a roundtrip of env values into the config", async () => {
      process.env[ENV_SECRET] = "env-secret-0123456789abcdef0123456789";
      process.env[ENV_EXPIRY] = "2h";
      process.env[ENV_VERIFY_URL] = "https://idp.test/.well-known/jwks.json";
      process.env[ENV_CLOCK_TOLERANCE] = "30";

      const { config } = await svc.initialize({});
      expect(config.secret).toBe("env-secret-0123456789abcdef0123456789");
      expect(config.expiry).toBe("2h");
      expect(config.verifyUrl).toBe("https://idp.test/.well-known/jwks.json");
      expect(config.clockToleranceSeconds).toBe(30);
    });

    it("should let explicit config override env values", async () => {
      process.env[ENV_SECRET] = "env-secret-0123456789abcdef0123456789";
      process.env[ENV_EXPIRY] = "2h";

      const { config } = await svc.initialize({
        secret: "explicit-secret-0123456789abcdef0123456789",
      });
      expect(config.secret).toBe("explicit-secret-0123456789abcdef0123456789");
      expect(config.expiry).toBe("2h");
    });

    it("should ignore a non-numeric clock tolerance value", async () => {
      process.env[ENV_CLOCK_TOLERANCE] = "not-a-number";
      const { config } = await svc.initialize({});
      expect(config.clockToleranceSeconds).toBeUndefined();
    });

    it("should ignore a non-finite clock tolerance value", async () => {
      process.env[ENV_CLOCK_TOLERANCE] = "Infinity";
      const { config } = await svc.initialize({});
      expect(config.clockToleranceSeconds).toBeUndefined();
    });

    it("should leave fields unset when the env var is absent", async () => {
      const { config } = await svc.initialize({});
      expect(config.secret).toBeUndefined();
      expect(config.expiry).toBeUndefined();
      expect(config.verifyUrl).toBeUndefined();
      expect(config.clockToleranceSeconds).toBeUndefined();
    });

    it("should parse a partial integer clock tolerance string", async () => {
      process.env[ENV_CLOCK_TOLERANCE] = "10.9";
      const { config } = await svc.initialize({});
      expect(config.clockToleranceSeconds).toBe(10);
    });
  });

  describe("default algorithm pinning", () => {
    let svcWithSecret: JwtService;

    beforeEach(async () => {
      svcWithSecret = await bootService({ secret: SECRET, expiry: "1h" });
    });

    it("should sign with the default HS256 algorithm and JWT typ", async () => {
      const { access_token } = await svcWithSecret.createAuthJwt({ sub: "u1" });
      const header = headerOf(access_token);
      expect(header.alg).toBe("HS256");
      expect(header.typ).toBe("JWT");
    });

    it("should default the expiry to 5 minutes when none is provided", async () => {
      const service = await bootService({ secret: SECRET });
      const { access_token } = await service.createAuthJwt({ sub: "u1" });
      const { exp } = payloadOf(access_token);
      const now = Math.floor(Date.now() / 1000);
      expect(exp as number).toBeGreaterThanOrEqual(now + 295);
      expect(exp as number).toBeLessThanOrEqual(now + 305);
    });

    it("should reject a token signed with a different algorithm", async () => {
      const token = await new SignJWT({ sub: "u1" })
        .setProtectedHeader({ alg: "HS384", typ: "JWT" })
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(new TextEncoder().encode(SECRET));

      await expect(svcWithSecret.decodeJwt(token)).rejects.toThrow(
        "Invalid token"
      );
    });
  });

  describe("sign / verify roundtrip", () => {
    let svcWithSecret: JwtService;

    beforeEach(async () => {
      svcWithSecret = await bootService({ secret: SECRET, expiry: "1h" });
    });

    it("should roundtrip a payload through createAuthJwt and decodeAuthToken", async () => {
      const { access_token } = await svcWithSecret.createAuthJwt({
        sub: "user-42",
        role: "admin",
      });
      const payload = await svcWithSecret.decodeAuthToken(access_token);
      expect(payload).toEqual(expect.objectContaining({ sub: "user-42" }));
    });

    it("should roundtrip via decodeJwt", async () => {
      const { access_token } = await svcWithSecret.createAuthJwt({ sub: "u" });
      const payload = await svcWithSecret.decodeJwt(access_token);
      expect(payload).toEqual(expect.objectContaining({ sub: "u" }));
    });

    it("should verify a token produced by the raw sign function", async () => {
      const token = await sign({ sub: "raw-path" }, { secret: SECRET });
      const payload = await svcWithSecret.decodeJwt(token);
      expect(payload.sub).toBe("raw-path");
    });
  });

  describe("error handling", () => {
    it("should reject signing when no secret is configured", async () => {
      const service = await bootService({});
      await expect(service.createAuthJwt({ sub: "u" })).rejects.toThrow(
        "Missing JWT secret"
      );
    });

    it("should reject verification with an incorrect secret", async () => {
      const signer = await bootService({ secret: SECRET, expiry: "1h" });
      const { access_token } = await signer.createAuthJwt({ sub: "u" });
      const verifier = await bootService({
        secret: "another-secret-0123456789abcdef0123456789",
      });
      await expect(verifier.decodeJwt(access_token)).rejects.toThrow(
        "Invalid token"
      );
    });

    it("should reject a tampered token", async () => {
      const signer = await bootService({ secret: SECRET, expiry: "1h" });
      const { access_token } = await signer.createAuthJwt({ sub: "u" });
      await expect(signer.decodeJwt(access_token + "tamper")).rejects.toThrow(
        "Invalid token"
      );
    });
  });

  describe("verifyJwt decode-only fail-closed", () => {
    const decodeOnlyToken =
      "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkZWNvZGUtb25seSJ9.c2lnbmF0dXJl";

    it("should throw InternalError when neither secret nor verifyUrl is set and allowDecodeOnly is not set", async () => {
      await expect(verifyJwt(decodeOnlyToken, {})).rejects.toThrow(
        InternalError
      );
      await expect(verifyJwt(decodeOnlyToken, {})).rejects.toThrow(
        "JWT verification is not configured"
      );
    });

    it("should return the unverified payload only when allowDecodeOnly is explicitly true", async () => {
      const payload = await verifyJwt(decodeOnlyToken, {
        allowDecodeOnly: true,
      });
      expect(payload.sub).toBe("decode-only");
    });

    it("should still reject an unparseable token when allowDecodeOnly is true", async () => {
      await expect(
        verifyJwt("not-a-jwt", { allowDecodeOnly: true })
      ).rejects.toThrow("Invalid token");
    });
  });

  describe("verifyJwt HS256 path", () => {
    const HS_SECRET = "unit-test-jwt-secret-that-is-at-least-32-bytes!";

    it("should reject a forged token signed with a different secret", async () => {
      const token = await new SignJWT({ sub: "attacker", admin: true })
        .setProtectedHeader({ alg: "HS256", typ: "JWT" })
        .setIssuedAt()
        .setExpirationTime("5m")
        .sign(
          new TextEncoder().encode("another-secret-0123456789abcdef0123456789")
        );

      await expect(verifyJwt(token, { secret: HS_SECRET })).rejects.toThrow(
        "Invalid token"
      );
    });

    it("should accept an exp-drifted token within the configured clock tolerance", async () => {
      const now = Math.floor(Date.now() / 1000);
      const token = await new SignJWT({ sub: "late-user" })
        .setProtectedHeader({ alg: "HS256", typ: "JWT" })
        .setIssuedAt(now - 600)
        .setExpirationTime(now - 3)
        .sign(new TextEncoder().encode(HS_SECRET));

      const payload = await verifyJwt(token, {
        secret: HS_SECRET,
        clockToleranceSeconds: 10,
      });
      expect(payload.sub).toBe("late-user");
    });

    it("should reject an exp-drifted token beyond the configured clock tolerance", async () => {
      const now = Math.floor(Date.now() / 1000);
      const token = await new SignJWT({ sub: "too-late" })
        .setProtectedHeader({ alg: "HS256", typ: "JWT" })
        .setIssuedAt(now - 6000)
        .setExpirationTime(now - 120)
        .sign(new TextEncoder().encode(HS_SECRET));

      await expect(
        verifyJwt(token, { secret: HS_SECRET, clockToleranceSeconds: 10 })
      ).rejects.toThrow("Invalid token");
    });
  });

  describe("decode-only warning", () => {
    it("should log a warning when allowDecodeOnly is enabled during initialize", async () => {
      const warnSpy = jest.spyOn(Logging.get(), "warn");
      try {
        const { config } = await new JwtService().initialize({
          allowDecodeOnly: true,
        });
        expect(config.allowDecodeOnly).toBe(true);
        expect(warnSpy).toHaveBeenCalled();
        const message = warnSpy.mock.calls
          .map((call) => String(call[0]))
          .join(" ");
        expect(message.toLowerCase()).toContain("not verified");
      } finally {
        warnSpy.mockRestore();
      }
    });
  });
});
