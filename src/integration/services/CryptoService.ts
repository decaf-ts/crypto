import { description } from "@decaf-ts/decoration";
import {
  ClientBasedService,
  MaybeContextualArg,
  PersistenceKeys,
} from "@decaf-ts/core";
import { Pbkdf2Hash } from "../../node/pbkdf2";
import { Crypto } from "../../node/Crypto";
import { getCrypto } from "../../common/crypto";
import { getSubtle } from "../../common/subtle-crypto";
import { InternalError } from "@decaf-ts/db-decorators";


export interface Pbkdf2PolicyConfig {
  /**
   * Pinned default iteration count for the PBKDF2 policy.
   * @default 150_000
   */
  iterations?: number;
  /**
   * Pinned hash algorithm for the PBKDF2 policy.
   * @default "sha256"
   */
  hash?: string;
  /**
   * Minimum iteration count considered safe under the policy. When a hash is
   * produced or verified with fewer iterations, a warning is surfaced.
   * @default 100_000
   */
  minIterations?: number;
}

export interface CryptoServiceConfig {
  /**
   * AES-GCM algorithm configuration
   * @default { length: 256 }
   */
  aesGcm?: { length: 128 | 192 | 256 };
  /**
   * IV length in bytes for AES-GCM
   * @default 12 (96 bits - recommended for GCM)
   */
  ivLength?: number;
  /**
   * PBKDF2 parameter policy. Values are pinned here so callers who do not
   * override them always derive/verify with the configured safe defaults.
   */
  pbkdf2?: Pbkdf2PolicyConfig;
}

const DEFAULT_AES_GCM = { length: 256 } as const;
const DEFAULT_IV_LENGTH = 12;
const DEFAULT_PBKDF2_ITERATIONS = 150_000;
const DEFAULT_PBKDF2_HASH = "sha256";
const DEFAULT_PBKDF2_MIN_ITERATIONS = 100_000;

@description("Secure cryptographic operations service")
export class CryptoService extends ClientBasedService<typeof Crypto, CryptoServiceConfig> {
  constructor() {
    super();
  }

  async initialize(
    ...args: MaybeContextualArg<any>
  ): Promise<{ config: CryptoServiceConfig; client: typeof Crypto }> {
    const { log } = (
      await this.logCtx(args, PersistenceKeys.INITIALIZATION, true)
    ).for(this.initialize);
    const cfg = (args[0] as CryptoServiceConfig | undefined) ?? {};
    const client = await getCrypto();
    log.verbose(`Loaded crypto`);
    return Promise.resolve({ config: cfg, client: client as typeof Crypto });
  }

  /**
   * Get the configured AES-GCM algorithm parameters
   */
  protected get aesGcmAlgorithm(): { length: 128 | 192 | 256 } {
    return this.config.aesGcm || DEFAULT_AES_GCM;
  }

  /**
   * Get the configured IV length
   */
  protected get ivLength(): number {
    return this.config.ivLength ?? DEFAULT_IV_LENGTH;
  }

  /**
   * Get the pinned PBKDF2 parameter policy.
   */
  protected get pbkdf2Policy(): Required<Pbkdf2PolicyConfig> {
    const policy = this.config.pbkdf2 ?? {};
    return {
      iterations: policy.iterations ?? DEFAULT_PBKDF2_ITERATIONS,
      hash: policy.hash ?? DEFAULT_PBKDF2_HASH,
      minIterations: policy.minIterations ?? DEFAULT_PBKDF2_MIN_ITERATIONS,
    };
  }

  /**
   * Surface a warning when the given iteration count is below the pinned policy
   * minimum. Logging goes through the service ctx logger.
   */
  protected warnIfBelowPolicy(iterations: number): void {
    const { minIterations, iterations: pinned } = this.pbkdf2Policy;
    if (iterations < minIterations) {
      this.log.warn(
        `PBKDF2 iteration count ${iterations} is below the pinned policy minimum of ${minIterations} (policy default ${pinned}). Use at least ${minIterations} iterations.`
      );
    }
  }

  protected genSalt(bytes = 16): Buffer {
    return this.client.randomBytes(bytes);
  }

  /**
   * Derive a key from a password using PBKDF2-HMAC-SHA256.
   * @param password plaintext password
   * @param iterations iteration count (e.g., 100_000+)
   * @param dkLen derived key length in bytes (e.g., 32)
   * @param salt optional salt (random if omitted)
   */
  async pbkdf2Hash(
    password: string,
    iterations = this.pbkdf2Policy.iterations,
    dkLen = 32,
    salt?: Buffer
  ): Promise<Pbkdf2Hash> {
    this.warnIfBelowPolicy(iterations);
    const saltBuf = salt ?? this.genSalt(16);
    const hash = this.client.pbkdf2Sync(
      password,
      saltBuf,
      iterations,
      dkLen,
      this.pbkdf2Policy.hash
    );
    return {
      saltB64: saltBuf.toString("base64"),
      hashB64: hash.toString("base64"),
      iterations,
      dkLen,
    };
  }

  verifyPbkdf2(password: string, rec: Pbkdf2Hash): boolean {
    this.warnIfBelowPolicy(rec.iterations);
    const salt = Buffer.from(rec.saltB64, "base64");
    const hash = this.client.pbkdf2Sync(
      password,
      salt,
      rec.iterations,
      rec.dkLen,
      this.pbkdf2Policy.hash
    );
    const stored = Buffer.from(rec.hashB64, "base64");
    if (stored.length !== hash.length) return false;
    return this.client.timingSafeEqual(stored, hash);
  }

  /**
   * Derive a key from a secret string using PBKDF2.
   * Returns salt + key combined as base64 string.
   *
   * NOTE: this keeps the historical 100_000-iteration default rather than the
   * policy default so previously-derived keys (and any ciphertext derived from
   * them) remain decryptable. The hash algorithm follows the pinned policy.
   * @param secret the secret string to derive key from
   * @param salt optional base64-encoded salt
   * @returns base64-encoded salt + key combination
   */
  async deriveKeyFromSecret(secret: string, salt?: string): Promise<string> {
    const saltBuffer = salt ? Buffer.from(salt, "base64") : this.genSalt(16);
    const key = this.client.pbkdf2Sync(
      secret,
      saltBuffer,
      100_000,
      32,
      this.pbkdf2Policy.hash
    );
    return Buffer.concat([saltBuffer, key]).toString("base64");
  }

  /**
   * Extract salt and key from a derived key string.
   * @param derivedKey base64-encoded salt + key combination
   * @returns object with salt and key as base64 strings
   */
  extractKeyFromDerivedKey(derivedKey: string): {
    salt: string;
    key: string;
  } {
    const buffer = Buffer.from(derivedKey, "base64");
    const salt = buffer.slice(0, 16).toString("base64");
    const key = buffer.slice(16).toString("base64");
    return { salt, key };
  }

  /**
   * Encrypt a payload using AES-GCM with automatic key derivation from secret.
   * @param payload plaintext to encrypt
   * @param secret secret string to derive encryption key from
   * @returns object with encrypted data (base64), IV, and salt for decryption
   */
  async encrypt(
    payload: string,
    secret: string
  ): Promise<{
    encryptedData: string;
    iv: string;
    salt: string;
  }> {
    try {
      const derivedKey = await this.deriveKeyFromSecret(secret);
      const { key, salt } = this.extractKeyFromDerivedKey(derivedKey);
      const keyBuffer = Buffer.from(key, "base64");

      const subtle = await getSubtle();
      const iv = this.genSalt(this.ivLength);
      const algorithm = { name: "AES-GCM", ...this.aesGcmAlgorithm };
      const importedKey = await subtle.importKey(
        "raw",
        keyBuffer,
        algorithm,
        false,
        ["encrypt"]
      );

      const encoder = new TextEncoder();
      const data = encoder.encode(payload);
      const encryptedBuffer = await subtle.encrypt(
        {
          ...algorithm,
          iv: iv,
        },
        importedKey,
        data
      );

      const encryptedBytes = new Uint8Array(encryptedBuffer);
      const combined = new Uint8Array(this.ivLength + encryptedBytes.length);
      combined.set(iv);
      combined.set(encryptedBytes, this.ivLength);

      return {
        encryptedData: Buffer.from(combined).toString("base64"),
        iv: iv.toString("base64"),
        salt,
      };
    } catch (error) {
      throw new InternalError(
        `Failed to encrypt payload: ${(error as Error).message}`
      );
    }
  }

  /**
   * Decrypt an encrypted payload using AES-GCM with automatic key derivation from secret.
   * @param encryptedData base64-encoded encrypted data (IV + ciphertext)
   * @param secret secret string to derive decryption key from
   * @param salt base64-encoded salt used during encryption (required for key derivation)
   * @returns decrypted plaintext string
   */
  async decrypt(
    encryptedData: string,
    secret: string,
    salt: string
  ): Promise<string> {
    try {
      const derivedKey = await this.deriveKeyFromSecret(secret, salt);
      const { key } = this.extractKeyFromDerivedKey(derivedKey);

      const subtle = await getSubtle();
      const combined = Buffer.from(encryptedData, "base64");
      const iv = combined.slice(0, this.ivLength);
      const cipherText = combined.slice(this.ivLength);

      const keyBuffer = Buffer.from(key, "base64");
      const algorithm = { name: "AES-GCM", ...this.aesGcmAlgorithm };
      const importedKey = await subtle.importKey(
        "raw",
        keyBuffer,
        algorithm,
        false,
        ["decrypt"]
      );

      const decryptedBuffer = await subtle.decrypt(
        {
          ...algorithm,
          iv: iv,
        },
        importedKey,
        cipherText
      );

      const decoder = new TextDecoder();
      return decoder.decode(decryptedBuffer);
    } catch (error) {
      throw new InternalError(
        `Failed to decrypt payload: ${(error as Error).message}`
      );
    }
  }

  /**
   * Low-level encrypt with pre-derived key (for advanced use cases).
   * @internal
   */
  async encryptPayload(
    payload: string,
    keyId: string,
    key: string
  ): Promise<{
    encryptedData: string;
    metadata: { keyId: string; iv: string };
  }> {
    try {
      const subtle = await getSubtle();
      const salt = this.genSalt(this.ivLength);
      const keyBuffer = Buffer.from(key, "base64");
      const algorithm = { name: "AES-GCM", ...this.aesGcmAlgorithm };
      const importedKey = await subtle.importKey(
        "raw",
        keyBuffer,
        algorithm,
        false,
        ["encrypt"]
      );

      const encoder = new TextEncoder();
      const data = encoder.encode(payload);
      const encryptedBuffer = await subtle.encrypt(
        {
          ...algorithm,
          iv: salt,
        },
        importedKey,
        data
      );

      const encryptedBytes = new Uint8Array(encryptedBuffer);
      const combined = new Uint8Array(this.ivLength + encryptedBytes.length);
      combined.set(salt);
      combined.set(encryptedBytes, this.ivLength);

      return {
        encryptedData: Buffer.from(combined).toString("base64"),
        metadata: {
          keyId,
          iv: salt.toString("base64"),
        },
      };
    } catch (error) {
      throw new InternalError(
        `Failed to encrypt payload: ${(error as Error).message}`
      );
    }
  }

  /**
   * Low-level decrypt with pre-derived key (for advanced use cases).
   * @internal
   */
  async decryptPayload(encryptedData: string, key: string): Promise<string> {
    try {
      const subtle = await getSubtle();
      const combined = Buffer.from(encryptedData, "base64");
      const iv = combined.slice(0, this.ivLength);
      const cipherText = combined.slice(this.ivLength);

      const keyBuffer = Buffer.from(key, "base64");
      const algorithm = { name: "AES-GCM", ...this.aesGcmAlgorithm };
      const importedKey = await subtle.importKey(
        "raw",
        keyBuffer,
        algorithm,
        false,
        ["decrypt"]
      );

      const decryptedBuffer = await subtle.decrypt(
        {
          ...algorithm,
          iv: iv,
        },
        importedKey,
        cipherText
      );

      const decoder = new TextDecoder();
      return decoder.decode(decryptedBuffer);
    } catch (error) {
      throw new InternalError(
        `Failed to decrypt payload: ${(error as Error).message}`
      );
    }
  }
}
