import { BufferLike, toBuffer } from './encoding';

/**
 * @description Encodes data into Base64 format.
 * @summary This function takes a buffer-like input and encodes it into a Base64 string.
 * @param {BufferLike} data - The data to encode.
 * @returns {string} The Base64 encoded string.
 * @function encodeBase64
 * @memberOf module:@decaf-ts/crypto/psk
 */
export function encodeBase64(data: BufferLike): string {
  return toBuffer(data).toString('base64');
}

/**
 * @description Decodes a Base64 encoded string.
 * @summary This function takes a Base64 encoded string and decodes it into a Buffer.
 * @param {string} source - The Base64 encoded string.
 * @returns {Buffer} The decoded buffer.
 * @function decodeBase64
 * @memberOf module:@decaf-ts/crypto/psk
 */
export function decodeBase64(source: string): Buffer {
  return Buffer.from(source, 'base64');
}

/**
 * @description Encodes data into a URL-safe Base64 format.
 * @summary This function encodes data into Base64 and then makes it URL-safe by removing `+`, `/`, and `=` characters.
 * @param {BufferLike} data - The data to encode.
 * @returns {string} The URL-safe Base64 encoded string.
 * @function encodeBase64UrlSafe
 * @memberOf module:@decaf-ts/crypto/psk
 */
export function encodeBase64UrlSafe(data: BufferLike): string {
  return encodeBase64(data).replace(/\+/g, '').replace(/\//g, '').replace(/=+$/, '');
}
