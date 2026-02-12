if (!(globalThis as any).window || !(globalThis as any).window.crypto)
  throw new Error(
    `You don't seem to be in a browser environment capable to supporting subtle crypto`
  );

/**
 * @description The browser's native `Crypto` object.
 * @summary
 * This constant exports the `crypto` object from the `window` object, providing
 * access to its `getRandomValues` and `randomUUID` methods.
 *
 * An error is thrown if the code is not running in a browser environment that supports `window.crypto`.
 * @const {object} Crypto
 * @type {{getRandomValues<T extends ArrayBufferView>(array: T): T; randomUUID(): string;}}
 * @memberOf module:@decaf-ts/crypto/browser
 */
export const Crypto = (globalThis as any).window.crypto as {
  getRandomValues<T extends ArrayBufferView>(array: T): T;
  randomUUID(): string;
};
