import crypto from 'crypto';
import { BufferLike, toBuffer } from '../utils/encoding';

/**
 * @description A class for computing a PSK hash (SHA-512 then SHA-256).
 * @summary This class provides a streaming interface for computing a hash by first applying SHA-512 and then SHA-256 to the result.
 * @class PskHash
 * @memberOf module:@decaf-ts/crypto/psk
 */
export class PskHash {
  private readonly sha512 = crypto.createHash('sha512');

  /**
   * @description Updates the hash content with the given data.
   * @summary This method updates the internal SHA-512 hash object with a new chunk of data.
   * @param {BufferLike} value - The data to add to the hash.
   * @returns {this} The `PskHash` instance for chaining.
   * @function update
   * @memberOf module:@decaf-ts/crypto/psk
   */
  update(value: BufferLike): this {
    this.sha512.update(toBuffer(value));
    return this;
  }

  /**
   * @description Computes and returns the final hash.
   * @summary This method first computes the SHA-512 digest of all the data that has been updated. It then computes the SHA-256 digest of the SHA-512 result and returns it.
   * @param {crypto.BinaryToTextEncoding} [encoding] - The encoding for the output hash. If not provided, a Buffer is returned.
   * @returns {Buffer | string} The computed hash as a Buffer or a string.
   * @function digest
   * @memberOf module:@decaf-ts/crypto/psk
   */
  digest(encoding?: crypto.BinaryToTextEncoding): Buffer | string {
    const sha256 = crypto.createHash('sha256');
    sha256.update(this.sha512.digest());
    return encoding ? sha256.digest(encoding) : sha256.digest();
  }
}
