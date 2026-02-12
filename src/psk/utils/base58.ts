import { BufferLike, toBuffer } from './encoding';

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE = ALPHABET.length;
const LEADER = ALPHABET[0];
const FACTOR = Math.log(BASE) / Math.log(256);
const IFACTOR = Math.log(256) / Math.log(BASE);

const BASE_MAP = Buffer.alloc(256, 255);
for (let i = 0; i < ALPHABET.length; i++) {
  const code = ALPHABET.charCodeAt(i);
  if (BASE_MAP[code] !== 255) {
    throw new TypeError(`${ALPHABET[i]} is ambiguous`);
  }
  BASE_MAP[code] = i;
}

/**
 * @description Encodes data into Base58 format.
 * @summary This function takes a buffer-like input and encodes it into a Base58 string.
 * @param {BufferLike} source - The data to encode.
 * @returns {string} The Base58 encoded string.
 * @function encode
 * @memberOf module:@decaf-ts/crypto/psk
 */
export function encode(source: BufferLike): string {
  const buffer = toBuffer(source);
  if (buffer.length === 0) {
    return '';
  }

  let zeroes = 0;
  let length = 0;
  let pbegin = 0;
  const pend = buffer.length;

  while (pbegin !== pend && buffer[pbegin] === 0) {
    pbegin++;
    zeroes++;
  }

  const size = ((pend - pbegin) * IFACTOR + 1) >>> 0;
  const b58 = Buffer.alloc(size);

  while (pbegin !== pend) {
    let carry = buffer[pbegin];
    let i = 0;
    for (let it = size - 1; (carry !== 0 || i < length) && it !== -1; it--, i++) {
      carry += (256 * b58[it]) >>> 0;
      b58[it] = (carry % BASE) >>> 0;
      carry = (carry / BASE) >>> 0;
    }
    if (carry !== 0) {
      throw new Error('Non-zero carry');
    }
    length = i;
    pbegin++;
  }

  let it = size - length;
  while (it !== size && b58[it] === 0) {
    it++;
  }

  let result = LEADER.repeat(zeroes);
  for (; it < size; ++it) {
    result += ALPHABET.charAt(b58[it]);
  }

  return result;
}

/**
 * @description Decodes a Base58 encoded string.
 * @summary This function takes a Base58 encoded string and decodes it into a Buffer.
 * @param {string} source - The Base58 encoded string.
 * @returns {Buffer} The decoded buffer.
 * @throws {Error} If the input string contains invalid characters.
 * @function decode
 * @memberOf module:@decaf-ts/crypto/psk
 */
export function decode(source: string): Buffer {
  if (source.length === 0) {
    return Buffer.alloc(0);
  }
  let psz = 0;
  if (source[psz] === ' ') {
    return Buffer.alloc(0);
  }

  let zeroes = 0;
  let length = 0;
  while (source[psz] === LEADER) {
    zeroes++;
    psz++;
  }

  const size = (((source.length - psz) * FACTOR) + 1) >>> 0;
  const b256 = Buffer.alloc(size);

  while (source[psz]) {
    const carry = BASE_MAP[source.charCodeAt(psz)];
    if (carry === 255) {
      throw new Error('Invalid character for base58');
    }
    let i = 0;
    let ci = carry;
    for (let it = size - 1; (ci !== 0 || i < length) && it !== -1; it--, i++) {
      ci += BASE * b256[it];
      b256[it] = (ci % 256) >>> 0;
      ci = (ci / 256) >>> 0;
    }
    if (ci !== 0) {
      throw new Error('Non-zero carry');
    }
    length = i;
    psz++;
  }

  if (source[psz] === ' ') {
    throw new Error('Invalid whitespace in base58 input');
  }

  let it = size - length;
  while (it !== size && b256[it] === 0) {
    it++;
  }

  const dest = Buffer.alloc(zeroes + (size - it));
  dest.fill(0, 0, zeroes);
  let j = zeroes;
  while (it < size) {
    dest[j++] = b256[it++];
  }

  return dest;
}
