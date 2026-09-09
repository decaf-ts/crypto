/**
 * PR-2 platform-guard errors.
 *
 * The browser adapters (`src/browser/Subtle`, `src/browser/Crypto`) guard on module
 * import: they throw when there is no browser-like `globalThis.window`, so using them
 * from a non-browser (Node) environment fails fast instead of silently misbehaving.
 *
 * This suite asserts those guards. It runs in the Node jest environment where
 * `globalThis.window` is undefined by default, so the browser modules must reject.
 *
 * Note on the reverse direction (node adapter in a browser): `src/node/Subtle` and
 * `src/node/Crypto` carry no explicit guard -- they merely `import crypto` from Node's
 * built-in module, which simply does not exist in a real browser. There is no guard to
 * assert in a Node environment, so it cannot be exercised here; a browser runtime would
 * reject the import at module resolution. This is documented rather than asserted.
 */
describe("PR-2: platform-guard errors (browser adapter used on Node)", () => {
  beforeEach(() => {
    delete (globalThis as { window?: unknown }).window;
  });

  it("browser/Subtle throws when no browser window is present (Node)", () => {
    expect(() =>
      jest.requireActual("../../src/browser/Subtle")
    ).toThrow(/You don't seem to be in a browser environment/);
  });

  it("browser/Crypto throws when no browser window is present (Node)", () => {
    expect(() =>
      jest.requireActual("../../src/browser/Crypto")
    ).toThrow(/You don't seem to be in a browser environment/);
  });

  it("node/Subtle and node/Crypto load without a browser window", () => {
    const nodeSubtleModule = jest.requireActual("../../src/node/Subtle") as { Subtle: any };
    const nodeCryptoModule = jest.requireActual("../../src/node/Crypto") as { Crypto: any };
    expect(typeof nodeSubtleModule.Subtle.encrypt).toBe("function");
    expect(typeof nodeCryptoModule.Crypto.createCipheriv).toBe("function");
  });
});
