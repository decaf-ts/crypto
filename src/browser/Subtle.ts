import { SubtleCrypto } from "../common/Subtle";

if (!(globalThis as any).window || !(globalThis as any).window.crypto || !(globalThis as any).window.crypto.subtle)
  throw new Error(`You don't seem to be in a browser environment capable to supporting subtle crypto`)

/**
 * @description The browser's native `SubtleCrypto` implementation.
 * @summary
 * This constant exports the `SubtleCrypto` object from the Web Crypto API available in the browser.
 * It provides a low-level interface for cryptographic operations.
 *
 * An error is thrown if the code is not running in a browser environment that supports `SubtleCrypto`.
 * @const {SubtleCrypto}
 * @memberOf module:@decaf-ts/crypto/browser
 */
export const Subtle: SubtleCrypto = (globalThis as any).window.crypto.subtle as any;