import { normalizeImport } from "@decaf-ts/core";
import { SubtleCrypto } from "./Subtle";
import { InternalError } from "@decaf-ts/db-decorators";

/**
 * @description Dynamically provides the environment-specific `SubtleCrypto` implementation.
 * @summary
 * This function detects whether the code is running in a browser or Node.js environment
 * and dynamically imports the appropriate `SubtleCrypto` implementation.
 * @returns {Promise<SubtleCrypto>} A promise that resolves to the `SubtleCrypto` implementation for the current environment.
 * @throws {InternalError} If the `SubtleCrypto` implementation cannot be loaded.
 * @function getSubtle
 * @memberOf module:@decaf-ts/crypto
 *
 * @mermaid
 * sequenceDiagram
 *   participant Client
 *   participant getSubtle
 *   participant BrowserImpl as Browser SubtleCrypto
 *   participant NodeImpl as Node.js SubtleCrypto
 *
 *   Client->>getSubtle: Call getSubtle()
 *   getSubtle->>getSubtle: Check environment (browser or node)
 *   alt Browser Environment
 *     getSubtle->>BrowserImpl: Dynamically import
 *     BrowserImpl-->>getSubtle: SubtleCrypto instance
 *     getSubtle-->>Client: Returns Browser SubtleCrypto
 *   else Node.js Environment
 *     getSubtle->>NodeImpl: Dynamically import
 *     NodeImpl-->>getSubtle: SubtleCrypto instance
 *     getSubtle-->>Client: Returns Node.js SubtleCrypto
 *   end
 */
export async function getSubtle() {
  const isBrowser = !!(globalThis as any).window;

  let subtle: SubtleCrypto;
  try {
    if (isBrowser)
      subtle = (await normalizeImport(import("../browser/index"))).Subtle;
    else subtle = (await normalizeImport(import("../node/index"))).Subtle;
  } catch (e: unknown) {
    throw new InternalError(
      `Failed to load subtle crypto in ${isBrowser ? "browser" : "node"} environment: ${e}`
    );
  }
  return subtle;
}
