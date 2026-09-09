import { CryptoService } from "../../src/integration/services/CryptoService";

describe("CryptoService PBKDF2 policy pinning (PR-3)", () => {
  let cryptoService: CryptoService;
  let warnSpy: jest.SpyInstance;

  beforeAll(async () => {
    cryptoService = new CryptoService();
    await cryptoService.boot({});
  });

  beforeEach(() => {
    warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
  });

  afterEach(() => {
    warnSpy.mockRestore();
  });

  describe("pinned defaults", () => {
    it("pins the default iteration count at 150_000 when none is supplied", async () => {
      const hash = await cryptoService.pbkdf2Hash("policy-password");
      expect(hash.iterations).toBe(150_000);
      expect(hash.dkLen).toBe(32);
    });

    it("derives a hash that verifies with the default policy", async () => {
      const hash = await cryptoService.pbkdf2Hash("roundtrip-password");
      const ok = cryptoService.verifyPbkdf2("roundtrip-password", hash);
      expect(ok).toBe(true);
      expect(cryptoService.verifyPbkdf2("wrong-password", hash)).toBe(false);
    });

    it("produces a stable hash for a fixed salt and pinned iterations", async () => {
      const salt = Buffer.alloc(16, 7);
      const first = await cryptoService.pbkdf2Hash(
        "stable-password",
        150_000,
        32,
        salt
      );
      const second = await cryptoService.pbkdf2Hash(
        "stable-password",
        150_000,
        32,
        salt
      );
      expect(first.hashB64).toBe(second.hashB64);
      expect(first.saltB64).toBe(second.saltB64);
      expect(first.iterations).toBe(150_000);
    });
  });

  describe("below-threshold warning", () => {
    it("surfaces a warning when iterations are below the policy minimum", async () => {
      await cryptoService.pbkdf2Hash("weak-password", 50_000);
      expect(warnSpy).toHaveBeenCalled();
      const calls = warnSpy.mock.calls.map((c) => String(c[0]));
      expect(calls.some((c) => c.includes("below the pinned policy minimum"))).toBe(
        true
      );
    });

    it("does not warn at or above the policy minimum", async () => {
      await cryptoService.pbkdf2Hash("fine-password", 100_000);
      await cryptoService.pbkdf2Hash("fine-password", 150_000);
      expect(warnSpy).not.toHaveBeenCalled();
    });

    it("warns on verify when the stored record used below-threshold iterations", async () => {
      const weak = await cryptoService.pbkdf2Hash("legacy-password", 10_000);
      cryptoService.verifyPbkdf2("legacy-password", weak);
      const calls = warnSpy.mock.calls.map((c) => String(c[0]));
      expect(calls.some((c) => c.includes("below the pinned policy minimum"))).toBe(
        true
      );
    });
  });

  describe("custom policy configuration", () => {
    it("uses a configured pinned default when provided", async () => {
      const custom = new CryptoService();
      await custom.boot({
        pbkdf2: { iterations: 210_000, minIterations: 200_000 },
      });
      const hash = await custom.pbkdf2Hash("custom-password");
      expect(hash.iterations).toBe(210_000);
    });

    it("warns against a configured minimum threshold", async () => {
      const custom = new CryptoService();
      await custom.boot({
        pbkdf2: { iterations: 210_000, minIterations: 200_000 },
      });
      await custom.pbkdf2Hash("custom-password", 150_000);
      const calls = warnSpy.mock.calls.map((c) => String(c[0]));
      expect(calls.some((c) => c.includes("below the pinned policy minimum"))).toBe(
        true
      );
    });
  });
});
