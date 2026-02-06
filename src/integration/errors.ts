import { InternalError } from "@decaf-ts/db-decorators";

/**
 * @description Custom error class for cryptographic operations.
 * @summary
 * The `CryptoError` class extends `InternalError` and is used to represent errors that occur
 * during cryptographic operations within the `@decaf-ts/crypto` package.
 * @class CryptoError
 * @param {string | Error} msg - The error message or an existing Error object.
 * @example
 * try {
 *   // some cryptographic operation
 * } catch (e) {
 *   throw new CryptoError(e);
 * }
 */
export class CryptoError extends InternalError {
  constructor(msg: string | Error) {
    super(msg, CryptoError.name, 505);
  }
}
