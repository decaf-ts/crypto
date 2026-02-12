/**
 * @description Represents a type that can be converted to a Buffer.
 * @typedef {Buffer | ArrayBuffer | ArrayBufferView | string} BufferLike
 * @memberOf module:@decaf-ts/crypto/psk
 */
export type BufferLike = Buffer | ArrayBuffer | ArrayBufferView | string;

/**
 * @description Converts a `BufferLike` value to a Buffer.
 * @summary This function handles the conversion of various types (Buffer, string, ArrayBuffer, ArrayBufferView) to a Node.js Buffer.
 * @param {BufferLike} value - The value to convert.
 * @param {BufferEncoding} [encoding='utf8'] - The encoding to use if the value is a string.
 * @returns {Buffer} The converted Buffer.
 * @throws {TypeError} If the value cannot be converted to a Buffer.
 * @function toBuffer
 * @memberOf module:@decaf-ts/crypto/psk
 */
export function toBuffer(value: BufferLike, encoding: BufferEncoding = 'utf8'): Buffer {
  if (Buffer.isBuffer(value)) {
    return value;
  }

  if (typeof value === 'string') {
    return Buffer.from(value, encoding);
  }

  if (value instanceof ArrayBuffer) {
    return Buffer.from(value);
  }

  if (ArrayBuffer.isView(value)) {
    const view = value as ArrayBufferView;
    return Buffer.from(view.buffer, view.byteOffset, view.byteLength);
  }

  throw new TypeError('Value cannot be converted to Buffer.');
}

/**
 * @description Concatenates multiple buffers.
 * @summary This function is a wrapper around `Buffer.concat`.
 * @param {Buffer[]} buffers - The buffers to concatenate.
 * @returns {Buffer} The concatenated buffer.
 * @function concatBuffers
 * @memberOf module:@decaf-ts/crypto/psk
 */
export function concatBuffers(...buffers: Buffer[]): Buffer {
  return Buffer.concat(buffers);
}
