# Design Notes for Task 001

## Overview
We are porting the entire legacy `psk-crypto` library into the modern `@decaf-ts/crypto` codebase. The goal is to reproduce the public API surface (methods exposed by `PskCrypto`, helpers from `js-mutual-auth-ecies`, `jsonWebToken`, `jose`, and the `lib` helpers) using TypeScript, relying on native browser/node primitives and the up-to-date libraries listed in the constitution (`jose`, `eciesjs`, `jsonwebtoken`, `asn1`). Old redundancy (e.g., manual base64/base58 code, handwritten ASN.1 encoders) will be replaced with standard implementations whenever possible.

## Module Mapping
### src/psk/services
1. `PskCryptoService` (maps to `lib/PskCrypto.js`): handles signing, verifying, key derivation, hashing, base58, stream checks, random helpers, encryption helpers, and delegates to additional services for more complex flows.
2. `PskEncryptionService` (maps to `lib/PskEncryption.js`): modernizes encryption/decryption, using `crypto.createCipheriv`/`createDecipheriv` with authenticated mode support; returns deterministic outputs and exposes helper for parsing encryption envelopes.
3. `EciesCompatService` (maps to `js-mutual-auth-ecies`): wraps `eciesjs` for GE/DOA flows, exposes helpers for creating envelopes, verifying recipients, etc., but will use `eciesjs` primitives to avoid reimplementing KDF/cipher layers.
4. `JoseCompatService` (maps to `jose/index.js` and unused wrappers): reuses the official `jose` library; we will replicate helper functions for `sign`, `verify`, `encrypt`, `decrypt` while keeping the same API signatures.
5. `JwtCompatService` (maps to `jsonWebToken`): exposes `sign`, `verify`, `decode` employing `jsonwebtoken` for node compatibility and `jose` for browser/backwards compatibility.
6. `KeyGeneratorService` (maps to `ECKeyGenerator.js`): generates key pairs using `crypto.createECDH`, exposes conversion helpers to produce PEM/raw/DER outputs via `asn1`/`crypto` primitives.

### src/psk/utils
- `base58.ts` & `base64.ts`: keep the existing algorithms (lightweight) but remove `$$_` references and lean on `Buffer`/`TextEncoder` for conversions.
- `cryptoUtils.ts`: port `createPskHash`, `encode`, `generateSalt`, `generateSafeUid`, `getKeyLength`, `encryptionIsAuthenticated`, `convertPemToDer`, `convertDerPrivateKeyToRaw`, etc., but prefer native `Buffer`/`crypto` helpers and add typed interfaces.
- `encoding.ts`: helper for safe conversions between Buffer/string/ArrayBuffer to avoid repeated cast logic.

### src/psk/models
- `KeyPair.ts`: typed result for generated key pairs (private/public as `Buffer`).
- `PskHash.ts`: typed wrapper for the legacy `PskHash` object (SHA-512 accumulator + SHA-256 finalization).
- `PskEncryptedEnvelope`, etc., to model inputs from ECIES flows.

### src/psk/index.ts
- Exposes a default `PskCrypto` instance, re-exports helpers (`generateUid`, `hashValues`, `convertKeys`) while bridging to the new services to maintain compatibility.
- Ensures legacy method names stay intact (flat namespace) while delegating to `async`/`await` wrappers as needed.

## Testing Strategy
1. **Unit tests under `tests/unit/psk`**: port the old `generateKeyPairTest`, `uidGeneratorTest`, and `uidGeneratorBasicTest`, but refactor to target the new TypeScript service. Replace streaming/callback patterns with `async/await` and Node timers while asserting the same invariants.
2. **New coverage tests**: ensure we test hashing (`pskHash`, `hashValues`), base58 encoding round-trips, `PskEncryptionService` encrypt/decrypt cycles, and `KeyGeneratorService` conversion outputs.
3. **Mocks**: create deterministic RNG helpers to replace random behavior where needed (similar to `FakeGenerator`). The legacy UID tests already build pseudo-random sequences; we can port them but rely on `crypto.randomBytes` stubbed by jest.

## Redundancy Removals
- Replace manual JSON hashing loops (`ssutil.dumpObjectForHashing`) with a dedicated helper that normalizes objects + uses `crypto.createHash` rather than manual string concatenation when possible.
- Remove `$$_` indirection by referencing `Buffer` directly; use `TextEncoder`/`TextDecoder` or `Buffer.from` so code remains browser-compatible through existing polyfills.
- For ASN.1 conversions, use the `asn1` package (already in dependencies) and delegate to it instead of carrying over the legacy `lib/asn1` folder. We may add wrappers in `src/psk/utils/asn1Adapter.ts` if necessary.

## Next Implementation Focus
1. Scaffold directories (services, utils, models) and the new `src/psk/index.ts` entry point.
2. Begin porting the core `PskCryptoService` with `generateKeyPair`, `sign`, `verify`, `pskHash`, `pskBase58`, `randomBytes`, `deriveKey`, `hashValues`, `generateUid`, and `xorBuffers` ensuring synchronous flows keep their semantics while asynchronous flows use `async/await` (e.g., `generateKeyPair` returns a promise).
3. Add the `PskEncryptionService` with deterministic handling of IV/AAD/tag extraction plus a simple pairing with `KeyGeneratorService`.
4. Create Jest tests for the main methods plus ported UID tests; run `npm run lint`, `npm run build`, `npm run test` after code changes.

