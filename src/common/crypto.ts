import { normalizeImport } from "@decaf-ts/core";
import { InternalError } from "@decaf-ts/db-decorators";
import type { Crypto as WebCrypto } from "../browser/Crypto";
import type { Crypto } from "../node/Crypto";

/**
 * @description Dynamically provides the environment-specific `Crypto` object.
 * @summary This function detects whether the code is running in a browser or Node.js environment and dynamically imports the appropriate `Crypto` object.
 * @template BROWSER - A boolean literal type that is true if the environment is a browser.
 * @param {BROWSER} [isBrowser=!!(globalThis as any).window] - A boolean indicating whether the environment is a browser.
 * @returns {Promise<BROWSER extends true ? typeof WebCrypto : typeof Crypto>} A promise that resolves to the `Crypto` object for the current environment.
 * @throws {InternalError} If the `Crypto` object cannot be loaded.
 * @function getCrypto
 * @memberOf module:@decaf-ts/crypto
 */
export async function getCrypto<BROWSER extends boolean>(
  isBrowser: BROWSER = !!(globalThis as any).window as BROWSER
): Promise<BROWSER extends true ? typeof WebCrypto : typeof Crypto> {
  let crypto: any;
  try {
    if (isBrowser)
      crypto = (await normalizeImport(import("../browser/index"))).Crypto;
    else crypto = (await normalizeImport(import("../node/index"))).Crypto;
  } catch (e: unknown) {
    throw new InternalError(
      `Failed to load subtle crypto in ${isBrowser ? "browser" : "node"} environment: ${e}`
    );
  }
  return crypto;
}
