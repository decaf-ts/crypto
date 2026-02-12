import { SubtleCrypto } from "../common/Subtle";
import crypto from "crypto";

/**
 * @description The Node.js native `SubtleCrypto` implementation.
 * @summary
 * This constant exports the `SubtleCrypto` object from the Node.js `crypto` module.
 * It provides a low-level interface for cryptographic operations in a Node.js environment.
 * @const {SubtleCrypto} Subtle
 * @type {SubtleCrypto}
 * @memberOf module:@decaf-ts/crypto/node
 */
export const Subtle: SubtleCrypto = crypto.subtle as SubtleCrypto;
