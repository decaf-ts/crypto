import { Readable } from 'node:stream';
import fc from 'fast-check';
import { default as pskCrypto } from '../../src/psk';
import { legacyHashValues, legacyPskCrypto } from '../helpers/legacy-psk';

const toBuffer = (data: Uint8Array): Buffer => Buffer.from(data);

const normalizeBuffer = (value: Buffer | string): Buffer =>
  Buffer.isBuffer(value) ? value : Buffer.from(value, 'utf8');

const deriveLegacyStreamHash = (input: Buffer): Promise<Buffer> =>
  new Promise((resolve, reject) => {
    const stream = Readable.from([input]);
    legacyPskCrypto.pskHashStream(stream, (err, hash) => {
      if (err) {
        reject(err);
        return;
      }
      if (!hash) {
        reject(new Error('Legacy stream did not produce a hash'));
        return;
      }
      resolve(hash);
    });
  });

describe('psk-crypto compatibility fuzz suite', () => {
  test('pskHash matches legacy output for arbitrary buffers', async () => {
    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ minLength: 1, maxLength: 64 }), async (data) => {
        const buffer = toBuffer(data);
        const legacyHash = legacyPskCrypto.pskHash(buffer);
        const newHash = pskCrypto.pskHash(buffer);
        expect(normalizeBuffer(newHash).equals(normalizeBuffer(legacyHash))).toBe(true);
      }),
      { numRuns: 20 }
    );
  });

  test('hash(sha256) keeps parity with legacy implementation for strings', () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 64 }), (value) => {
        const legacy = legacyPskCrypto.hash('sha256', value);
        const current = pskCrypto.hash('sha256', value);
        expect(normalizeBuffer(current).equals(normalizeBuffer(legacy))).toBe(true);
      }),
      { numRuns: 20 }
    );
  });

  test('objectHash uses the same hashing strategy as the legacy version', () => {
    fc.assert(
      fc.property(
        fc.dictionary(
          fc.string({ minLength: 1, maxLength: 10 }),
          fc.oneof(fc.string(), fc.integer(), fc.boolean()),
          { maxKeys: 5 }
        ),
        (input) => {
          const legacy = legacyPskCrypto.objectHash('sha256', input);
          const current = pskCrypto.objectHash('sha256', input);
          expect(normalizeBuffer(current).equals(normalizeBuffer(legacy))).toBe(true);
        }
      ),
      { numRuns: 20 }
    );
  });

  test('base58 encode/decode stays compatible with legacy routines', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 1, maxLength: 64 }), (data) => {
        const buffer = toBuffer(data);
        const legacyEncoded = legacyPskCrypto.pskBase58Encode(buffer);
        const currentEncoded = pskCrypto.pskBase58Encode(buffer);
        expect(currentEncoded).toBe(legacyEncoded);

        const legacyDecoded = legacyPskCrypto.pskBase58Decode(currentEncoded);
        const currentDecoded = pskCrypto.pskBase58Decode(currentEncoded);
        expect(currentDecoded.equals(buffer)).toBe(true);
        expect(currentDecoded.equals(legacyDecoded)).toBe(true);
      }),
      { numRuns: 20 }
    );
  });

  test('base64 encode/decode stays compatible with legacy routines', () => {
    fc.assert(
      fc.property(fc.uint8Array({ minLength: 1, maxLength: 64 }), (data) => {
        const buffer = toBuffer(data);
        const legacyEncoded = legacyPskCrypto.pskBase64Encode(buffer);
        const currentEncoded = pskCrypto.pskBase64Encode(buffer);
        expect(currentEncoded).toBe(legacyEncoded);

        const legacyDecoded = legacyPskCrypto.pskBase64Decode(currentEncoded);
        const currentDecoded = pskCrypto.pskBase64Decode(currentEncoded);
        expect(currentDecoded.equals(buffer)).toBe(true);
        expect(currentDecoded.equals(legacyDecoded)).toBe(true);
      }),
      { numRuns: 20 }
    );
  });

  test('generateSafeUid produces identical outputs for matching inputs', () => {
    fc.assert(
      fc.property(
        fc.option(fc.string({ maxLength: 32 }), { nil: undefined }),
        fc.option(fc.string({ maxLength: 32 }), { nil: undefined }),
        (password, additional) => {
          const passwordBuffer = password ? Buffer.from(password, 'utf8') : Buffer.alloc(0);
          const additionalBuffer = additional ? Buffer.from(additional, 'utf8') : Buffer.alloc(0);
          const legacyUid = legacyPskCrypto.generateSafeUid(passwordBuffer, additionalBuffer);
          const currentUid = pskCrypto.generateSafeUid(passwordBuffer, additionalBuffer);
          expect(currentUid).toBe(legacyUid);
        }
      ),
      { numRuns: 20 }
    );
  });

  test('hashValues remains identical to the legacy implementation', () => {
    fc.assert(
      fc.property(
        fc.dictionary(
          fc.string({ minLength: 1, maxLength: 8 }),
          fc.oneof(fc.string(), fc.integer(), fc.boolean()),
          { maxKeys: 5 }
        ),
        (values) => {
          const legacyHash = legacyHashValues(values);
          const currentHash = pskCrypto.hashValues(values);
          expect(currentHash).toBe(legacyHash);
        }
      ),
      { numRuns: 20 }
    );
  });

  test('deriveKey is deterministic and matches legacy output', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 32 }),
        fc.integer({ min: 1000, max: 3000 }),
        (password, iterations) => {
          const passwordBuffer = Buffer.from(password, 'utf8');
          const legacy = legacyPskCrypto.deriveKey('aes-256-cbc', passwordBuffer, iterations);
          const current = pskCrypto.deriveKey('aes-256-cbc', passwordBuffer, iterations);
          expect(current.equals(legacy)).toBe(true);
        }
      ),
      { numRuns: 20 }
    );
  });

  test('xorBuffers honors legacy results and returns commutative outputs', () => {
    fc.assert(
      fc.property(
        fc.uint8Array({ minLength: 1, maxLength: 32 }),
        fc.uint8Array({ minLength: 1, maxLength: 32 }),
        (first, second) => {
          const bufferA = Buffer.from(first);
          const bufferB = Buffer.from(second);
          const legacyResult = legacyPskCrypto.xorBuffers(bufferA, bufferB);
          const currentResult = pskCrypto.xorBuffers(Buffer.from(first), Buffer.from(second));
          expect(currentResult.equals(legacyResult)).toBe(true);
        }
      ),
      { numRuns: 20 }
    );
  });

  test('pskHashStream matches legacy stream hashing', async () => {
    await fc.assert(
      fc.asyncProperty(fc.uint8Array({ minLength: 1, maxLength: 64 }), async (data) => {
        const buffer = Buffer.from(data);
        const newHash = await pskCrypto.pskHashStream(Readable.from([buffer]));
        const legacyHash = await deriveLegacyStreamHash(buffer);
        expect(normalizeBuffer(newHash).equals(normalizeBuffer(legacyHash))).toBe(true);
      }),
      { numRuns: 15 }
    );
  });
});
