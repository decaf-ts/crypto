import { Crypto } from "./Crypto";

export type Pbkdf2Hash = {
  saltB64: string;
  hashB64: string;
  iterations: number;
  dkLen: number;
};

function genSalt(bytes = 16): Buffer {
  return Crypto.randomBytes(bytes);
}

/**
 * Derive a key from a password using PBKDF2-HMAC-SHA256.
 * @param password plaintext password
 * @param iterations iteration count (e.g., 100_000+)
 * @param dkLen derived key length in bytes (e.g., 32)
 * @param salt optional salt (random if omitted)
 */
async function pbkdf2Hash(
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
