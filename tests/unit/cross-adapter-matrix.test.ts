/**
 * SAA-1084 / Decaf Framework Review V4 §9.2 PR-2.
 *
 * Cross-adapter matrix: assert identical AES-256-GCM encrypt/decrypt behavior
 * across the four adapter surfaces exposed by `@decaf-ts/crypto`:
 *
 *   src/node    × Subtle   (crypto.subtle            -- node WebCrypto)
 *   src/node    × Crypto   (crypto module            -- createCipheriv/createDecipheriv)
 *   src/browser × Subtle   (window.crypto.subtle     -- browser WebCrypto)
 *   src/browser × Crypto   (window.crypto            -- getRandomValues/randomUUID)
 *
 * The browser adapters are exercised in Node by installing a mock `globalThis.window`
 * whose `crypto` is Node's global WebCrypto object -- exactly the object the browser
 * adapters wrap -- so the whole matrix is runnable in the Node jest environment.
 *
 * PR-2's mandate is *identical behavior*, not just "it works in one backend":
 *   - round-trip within each encryption-capable adapter;
 *   - captured-ciphertext interoperability (encrypt with source, decrypt with target),
 *     the invariant V4 §9.2 tells us to assert (rather than raw byte equality where
 *     adapters legitimately differ);
 *   - byte-for-byte determinism for a fixed key/IV/plaintext (AES-GCM is deterministic).
 *
 * Deterministic fixtures are used so the assertions are stable and reproducible.
 */

type EncryptionAdapter = {
  name: string;
  encrypt(data: Uint8Array): Promise<Uint8Array>;
  decrypt(combined: Uint8Array): Promise<Uint8Array>;
};

const KEY_MATERIAL = new Uint8Array(32).map((_, i) => i); // 32 bytes -> AES-256
const IV = new Uint8Array(12).map((_, i) => 0x40 + (i % 16)); // 12 bytes -> GCM IV
const PLAINTEXT_UTF8 =
  "SAA-1084 cross-adapter matrix fixture: the quick brown fox jumps over the lazy dog";
const PLAINTEXT = new TextEncoder().encode(PLAINTEXT_UTF8);
const TAG_BYTES = 16; // AES-GCM 128-bit auth tag (WebCrypto default / createCipheriv default)

let nodeSubtle: EncryptionAdapter;
let nodeCrypto: EncryptionAdapter;
let browserSubtle: EncryptionAdapter;
let browserCrypto: {
  getRandomValues<T extends ArrayBufferView>(array: T): T;
  randomUUID(): string;
};

const ADAPTERS: [string, () => EncryptionAdapter][] = [
  ["node/Subtle", () => nodeSubtle],
  ["node/Crypto", () => nodeCrypto],
  ["browser/Subtle", () => browserSubtle],
];

function toText(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

/** Wrap a WebCrypto `SubtleCrypto` as a canonical combined-ciphertext adapter. */
function subtleAdapter(name: string, subtle: any): EncryptionAdapter {
  let key: any;
  const keyReady = subtle
    .importKey("raw", KEY_MATERIAL, { name: "AES-GCM", length: 256 }, false, [
      "encrypt",
      "decrypt",
    ])
    .then((k: any) => {
      key = k;
    });
  return {
    name,
    async encrypt(data: Uint8Array): Promise<Uint8Array> {
      await keyReady;
      return new Uint8Array(
        await subtle.encrypt({ name: "AES-GCM", iv: IV }, key, data)
      );
    },
    async decrypt(combined: Uint8Array): Promise<Uint8Array> {
      await keyReady;
      return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: IV }, key, combined));
    },
  };
}

/** Wrap Node's `crypto` cipheriv/decipheriv as a canonical combined-ciphertext adapter. */
function cryptoAdapter(name: string, nodeCrypto: any): EncryptionAdapter {
  const keyBuf = Buffer.from(KEY_MATERIAL);
  const ivBuf = Buffer.from(IV);
  return {
    name,
    async encrypt(data: Uint8Array): Promise<Uint8Array> {
      const cipher = nodeCrypto.createCipheriv("aes-256-gcm", keyBuf, ivBuf);
      const ciphertext = Buffer.concat([cipher.update(Buffer.from(data)), cipher.final()]);
      return new Uint8Array(Buffer.concat([ciphertext, cipher.getAuthTag()]));
    },
    async decrypt(combined: Uint8Array): Promise<Uint8Array> {
      const buf = Buffer.from(combined);
      const ciphertext = buf.subarray(0, buf.length - TAG_BYTES);
      const tag = buf.subarray(buf.length - TAG_BYTES);
      const decipher = nodeCrypto.createDecipheriv("aes-256-gcm", keyBuf, ivBuf);
      decipher.setAuthTag(tag);
      return new Uint8Array(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
    },
  };
}

/**
 * Install a browser-like `window` backed by Node's global WebCrypto and load the four
 * adapter modules via `jest.requireActual`. The browser adapters are thin wrappers over
 * `window.crypto`, so a mock `window` backed by `globalThis.crypto` is sufficient to
 * exercise them (Node's global WebCrypto already carries `.subtle`/`getRandomValues`/
 * `randomUUID`).
 */
function loadAdapters() {
  delete (globalThis as { window?: unknown }).window;
  (globalThis as { window?: unknown }).window = { crypto: globalThis.crypto };

  const nodeSubtleModule = jest.requireActual("../../src/node/Subtle") as { Subtle: any };
  const nodeCryptoModule = jest.requireActual("../../src/node/Crypto") as { Crypto: any };
  const browserSubtleModule = jest.requireActual("../../src/browser/Subtle") as { Subtle: any };
  const browserCryptoModule = jest.requireActual("../../src/browser/Crypto") as {
    Crypto: {
      getRandomValues<T extends ArrayBufferView>(array: T): T;
      randomUUID(): string;
    };
  };

  nodeSubtle = subtleAdapter("node/Subtle", nodeSubtleModule.Subtle);
  nodeCrypto = cryptoAdapter("node/Crypto", nodeCryptoModule.Crypto);
  browserSubtle = subtleAdapter("browser/Subtle", browserSubtleModule.Subtle);
  browserCrypto = browserCryptoModule.Crypto;
}

describe("PR-2: node/browser × Subtle|Crypto cross-adapter matrix", () => {
  beforeAll(() => {
    loadAdapters();
  });

  afterAll(() => {
    delete (globalThis as { window?: unknown }).window;
  });

  describe("round-trip within each encryption-capable adapter", () => {
    it.each(ADAPTERS)(
      "%s encrypts then decrypts to the original plaintext",
      async (_name, getAdapter) => {
        const adapter = getAdapter();
        const ciphertext = await adapter.encrypt(PLAINTEXT);
        const decrypted = await adapter.decrypt(ciphertext);
        expect(toText(decrypted)).toBe(PLAINTEXT_UTF8);
      }
    );

    it.each(ADAPTERS)(
      "%s emits a canonical ciphertext of ciphertext + 16-byte tag",
      async (_name, getAdapter) => {
        const adapter = getAdapter();
        const ciphertext = await adapter.encrypt(PLAINTEXT);
        expect(ciphertext.length).toBe(PLAINTEXT.length + TAG_BYTES);
        expect(ciphertext.length).toBeGreaterThan(PLAINTEXT.length);
      }
    );
  });

  describe("captured-ciphertext interoperability (encrypt with source, decrypt with target)", () => {
    it("every source ciphertext decrypts correctly in every target adapter", async () => {
      const adapters: Record<string, EncryptionAdapter> = {
        "node/Subtle": nodeSubtle,
        "node/Crypto": nodeCrypto,
        "browser/Subtle": browserSubtle,
      };

      for (const source of Object.values(adapters)) {
        const captured = await source.encrypt(PLAINTEXT);
        for (const target of Object.values(adapters)) {
          const decrypted = await target.decrypt(captured);
          expect(toText(decrypted)).toBe(PLAINTEXT_UTF8);
        }
      }
    });
  });

  describe("byte-for-byte determinism for a fixed key/IV/plaintext", () => {
    it("WebCrypto (node) and the mocked browser WebCrypto produce identical output", async () => {
      const nodeSubtleHex = toHex(await nodeSubtle.encrypt(PLAINTEXT));
      const browserSubtleHex = toHex(await browserSubtle.encrypt(PLAINTEXT));
      expect(nodeSubtleHex).toBe(browserSubtleHex);
    });

    it("Node createCipheriv AES-GCM agrees with WebCrypto for identical key/IV/plaintext", async () => {
      const nodeSubtleHex = toHex(await nodeSubtle.encrypt(PLAINTEXT));
      const nodeCryptoHex = toHex(await nodeCrypto.encrypt(PLAINTEXT));
      expect(nodeSubtleHex).toBe(nodeCryptoHex);
    });
  });

  describe("browser/Crypto surface (platform-crypto object: no encrypt/decrypt)", () => {
    it("exposes getRandomValues and randomUUID", () => {
      expect(typeof browserCrypto.getRandomValues).toBe("function");
      expect(typeof browserCrypto.randomUUID).toBe("function");

      const bytes = new Uint8Array(16);
      const filled = browserCrypto.getRandomValues(bytes);
      expect(filled).toBe(bytes);
      expect(bytes.some((b) => b !== 0)).toBe(true);

      const id = browserCrypto.randomUUID();
      expect(id).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
      );
    });
  });
});
