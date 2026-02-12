import { Crypto } from "./Crypto";

/**
 * @description Represents the result of a PBKDF2 hash operation.
 * @summary This type defines the structure of the object returned by the `pbkdf2Hash` function.
 * @typedef {object} Pbkdf2Hash
 * @property {string} saltB64 - The salt used for the hash, encoded in base64.
 * @property {string} hashB64 - The resulting hash, encoded in base64.
 * @property {number} iterations - The number of iterations used.
 * @property {number} dkLen - The derived key length in bytes.
 * @memberOf module:@decaf-ts/crypto/node
 */
export type Pbkdf2Hash = {
  saltB64: string;
  hashB64: string;
  iterations: number;
  dkLen: number;
};

/**
 * @description Generates a random salt.
 * @summary This function uses `crypto.randomBytes` to generate a random salt of the specified length.
 * @param {number} [bytes=16] - The number of bytes for the salt.
 * @returns {Buffer} A buffer containing the random salt.
 * @function genSalt
 * @memberOf module:@decaf-ts/crypto/node
 */
function genSalt(bytes = 16): Buffer {
  return Crypto.randomBytes(bytes);
}

/**
 * @description Derives a key from a password using PBKDF2-HMAC-SHA256.
 * @summary This function takes a password and other parameters to generate a PBKDF2 hash. If no salt is provided, a random one is generated.
 * @param {string} password - The plaintext password.
 * @param {number} [iterations=150000] - The iteration count.
 * @param {number} [dkLen=32] - The derived key length in bytes.
 * @param {Buffer} [salt] - An optional salt. If not provided, a random salt will be generated.
 * @returns {Promise<Pbkdf2Hash>} A promise that resolves to an object containing the salt, hash, iterations, and key length.
 * @function pbkdf2Hash
 * @memberOf module:@decaf-ts/crypto/node
 */
export async function pbkdf2Hash(
  password: string,
  iterations = 150_000,
  dkLen = 32,
  salt?: Buffer
): Promise<Pbkdf2Hash> {
  const saltBuf = salt ?? genSalt(16);
  const hash = Crypto.pbkdf2Sync(
    password,
    saltBuf,
    iterations,
    dkLen,
    "sha256"
  );
  return {
    saltB64: saltBuf.toString("base64"),
    hashB64: hash.toString("base64"),
    iterations,
    dkLen,
  };
}

/**
 * @description Verifies a password against a PBKDF2 hash.
 * @summary This function re-computes the PBKDF2 hash of the provided password using the stored salt, iterations, and key length, and then compares it in a timing-safe way to the stored hash.
 * @param {string} password - The plaintext password to verify.
 * @param {Pbkdf2Hash} rec - The stored PBKDF2 hash object.
 * @returns {boolean} True if the password is correct, false otherwise.
 * @function verifyPbkdf2
 * @memberOf module:@decaf-ts/crypto/node
 */
export function verifyPbkdf2(password: string, rec: Pbkdf2Hash): boolean {
  const salt = Buffer.from(rec.saltB64, "base64");
  const hash = Crypto.pbkdf2Sync(
    password,
    salt,
    rec.iterations,
    rec.dkLen,
    "sha256"
  );
  const stored = Buffer.from(rec.hashB64, "base64");
  if (stored.length !== hash.length) return false;
  return Crypto.timingSafeEqual(stored, hash);
}
