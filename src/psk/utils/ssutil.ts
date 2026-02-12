import crypto from 'crypto';

function createHashAlgorithm(): crypto.Hash {
  return crypto.createHash('sha256');
}

const HASH_LENGTH = 64;

/**
 * @description Wipes the content of a hex string outside a specified payload range.
 * @summary This function replaces the parts of a hex string that are outside the defined `pos` and `size` with zeroes.
 * @param {string} hashStringHexa - The hex string to modify.
 * @param {number} pos - The starting position of the payload.
 * @param {number} size - The size of the payload.
 * @returns {string} The modified hex string.
 * @function wipeOutsidePayload
 * @memberOf module:@decaf-ts/crypto/psk
 */
export function wipeOutsidePayload(hashStringHexa: string, pos: number, size: number): string {
  const sz = hashStringHexa.length;
  const end = (pos + size) % sz;

  if (pos < end) {
    return '0'.repeat(pos) + hashStringHexa.substring(pos, end) + '0'.repeat(sz - end);
  }

  return hashStringHexa.substring(0, end) + '0'.repeat(pos - end) + hashStringHexa.substring(pos, sz);
}

/**
 * @description Extracts a payload from a hex string.
 * @summary This function extracts a segment of a hex string defined by `pos` and `size`, handling wrap-around cases.
 * @param {string} hashStringHexa - The hex string to extract from.
 * @param {number} pos - The starting position of the payload.
 * @param {number} size - The size of the payload.
 * @returns {string} The extracted payload.
 * @function extractPayload
 * @memberOf module:@decaf-ts/crypto/psk
 */
export function extractPayload(hashStringHexa: string, pos: number, size: number): string {
  const sz = hashStringHexa.length;
  const end = (pos + size) % sz;

  if (pos < end) {
    return hashStringHexa.substring(pos, pos + size);
  }

  const prefix = end !== 0 ? hashStringHexa.substring(0, end) : '';
  return prefix + hashStringHexa.substring(pos, sz);
}

/**
 * @description Fills a payload into a zeroed string at a specified position.
 * @summary This function creates a zero-filled string and inserts the payload at the given `pos`.
 * @param {string} payload - The payload to insert.
 * @param {number} pos - The starting position for the payload.
 * @param {number} size - The size of the payload.
 * @returns {string} The resulting string.
 * @function fillPayload
 * @memberOf module:@decaf-ts/crypto/psk
 */
export function fillPayload(payload: string, pos: number, size: number): string {
  const sz = HASH_LENGTH;
  const end = (pos + size) % sz;

  if (pos < end) {
    return '0'.repeat(pos) + payload + '0'.repeat(sz - end);
  }

  let result = payload.substring(0, end);
  result += '0'.repeat(pos - end);
  result += payload.substring(end);
  return result;
}

/**
 * @description Generates a hash by repeatedly hashing a wiped payload.
 * @summary This function iteratively hashes a portion of a hex string, wiping the outside of the payload at each step.
 * @param {Buffer} buffer - The initial buffer to start with.
 * @param {number} pos - The starting position of the payload.
 * @param {number} size - The size of the payload.
 * @param {number} count - The number of hashing iterations.
 * @returns {string} The final wiped hash.
 * @function generatePosHashXTimes
 * @memberOf module:@decaf-ts/crypto/psk
 */
export function generatePosHashXTimes(buffer: Buffer, pos: number, size: number, count: number): string {
  let result = buffer.toString('hex');

  for (let i = 0; i < count; i += 1) {
    const hash = createHashAlgorithm();
    hash.update(wipeOutsidePayload(result, pos, size));
    result = hash.digest('hex');
  }

  return wipeOutsidePayload(result, pos, size);
}

/**
 * @description Hashes an array of strings with a counter.
 * @summary This function constructs a string by concatenating a counter and payloads extracted from an array of strings, and then hashes the result.
 * @param {number} counter - The counter value.
 * @param {string[]} arr - The array of strings to hash.
 * @param {number} payloadSize - The size of the payload to extract from each string.
 * @returns {string} The resulting hash as a hex string.
 * @function hashStringArray
 * @memberOf module:@decaf-ts/crypto/psk
 */
export function hashStringArray(counter: number, arr: string[], payloadSize: number): string {
  const hash = createHashAlgorithm();
  let result = counter.toString(16);

  for (let i = 0; i < 64; i += 1) {
    result += extractPayload(arr[i], i, payloadSize);
  }

  hash.update(result);
  return hash.digest('hex');
}

function dumpMember(obj: unknown): string {
  if (obj === null) {
    return 'null';
  }
  if (obj === undefined) {
    return 'undefined';
  }

  if (typeof obj === 'number' || typeof obj === 'string' || typeof obj === 'boolean') {
    return obj.toString();
  }

  if (Array.isArray(obj)) {
    return obj.map((value) => dumpMember(value)).join('');
  }

  if (typeof obj === 'object') {
    return dumpObjectForHashing(obj as Record<string, unknown>);
  }

  throw new Error(`Type ${(typeof obj).toString()} cannot be cryptographically digested`);
}

/**
 * @description Dumps an object to a canonical string for hashing.
 * @summary This function recursively converts an object to a string by sorting its keys and concatenating the key-value pairs.
 * @param {Record<string, unknown>} obj - The object to dump.
 * @returns {string} The canonical string representation.
 * @function dumpObjectForHashing
 * @memberOf module:@decaf-ts/crypto/psk
 */
export function dumpObjectForHashing(obj: Record<string, unknown>): string {
  const keys = Object.keys(obj).sort();
  return keys.reduce((acc, key) => acc + dumpMember(key) + dumpMember(obj[key]), '');
}

/**
 * @description Hashes a set of values.
 * @summary This function is a convenience wrapper around `dumpObjectForHashing` and `createHashAlgorithm`.
 * @param {unknown} values - The values to hash.
 * @returns {string} The resulting hash as a hex string.
 * @function hashValues
 * @memberOf module:@decaf-ts/crypto/psk
 */
export function hashValues(values: unknown): string {
  const hash = createHashAlgorithm();
  hash.update(dumpObjectForHashing(values as Record<string, unknown>));
  return hash.digest('hex');
}

/**
 * @description Parses a signature string into a JSON object.
 * @summary This function deconstructs a signature string (formatted as `agent:counter:nextPublic:proof`) into its constituent parts.
 * @param {string} signature - The signature string.
 * @param {number} size - The size of the payload segments in the proof.
 * @returns {{ agent: string; counter: number; nextPublic: string; proof: string[] }} The parsed signature object.
 * @throws {Error} If the signature is invalid.
 * @function getJSONFromSignature
 * @memberOf module:@decaf-ts/crypto/psk
 */
export function getJSONFromSignature(signature: string, size: number) {
  const segments = signature.split(':');
  const proofSegment = segments[3] || '';
  if (proofSegment.length / size !== HASH_LENGTH) {
    throw new Error(`Invalid signature ${proofSegment}`);
  }

  const proof: string[] = [];
  for (let i = 0; i < HASH_LENGTH; i += 1) {
    proof.push(fillPayload(proofSegment.substring(i * size, (i + 1) * size), i, size));
  }

  return {
    agent: segments[0],
    counter: parseInt(segments[1], 10),
    nextPublic: segments[2],
    proof,
  };
}

/**
 * @description Creates a signature string from its components.
 * @summary This function constructs a signature string by concatenating the agent, counter, nextPublic, and a payload extracted from an array.
 * @param {string} agent - The agent string.
 * @param {number} counter - The counter value.
 * @param {string} nextPublic - The next public key string.
 * @param {string[]} arr - The array to extract the payload from.
 * @param {number} size - The size of the payload to extract from each element of the array.
 * @returns {string} The formatted signature string.
 * @function createSignature
 * @memberOf module:@decaf-ts/crypto/psk
 */
export function createSignature(agent: string, counter: number, nextPublic: string, arr: string[], size: number): string {
  const payload = arr.map((value) => extractPayload(value, arr.indexOf(value), size)).join('');
  return `${agent}:${counter}:${nextPublic}:${payload}`;
}
