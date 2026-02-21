import { description } from "@decaf-ts/decoration";
import {
  ClientBasedService,
  MaybeContextualArg,
  PersistenceKeys,
} from "@decaf-ts/core";
import { Pbkdf2Hash } from "../../node/pbkdf2";
import { Crypto } from "../../node/Crypto";
import { getCrypto } from "src/common/crypto";
import { InternalError } from "@decaf-ts/db-decorators";

@description("Secure cryptographic operations service")
export class CryptoService extends ClientBasedService<typeof Crypto, any> {
  constructor() {
    super();
  }

  async initialize(
    ...args: MaybeContextualArg<any>
  ): Promise<{ config: any; client: typeof Crypto }> {
    const { log } = (
      await this.logCtx(args, PersistenceKeys.INITIALIZATION, true)
    ).for(this.initialize);
    const cfg = args[0];
    if (!cfg)
      throw new InternalError(`Missing configuration for CryptoService`);
    const client = await getCrypto();
    log.verbose(`Loaded crypto`);
    return Promise.resolve({ config: {}, client: client as typeof Crypto });
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
    iterations = 150_000,
    dkLen = 32,
    salt?: Buffer
  ): Promise<Pbkdf2Hash> {
    const saltBuf = salt ?? this.genSalt(16);
    const hash = this.client.pbkdf2Sync(
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

  verifyPbkdf2(password: string, rec: Pbkdf2Hash): boolean {
    const salt = Buffer.from(rec.saltB64, "base64");
    const hash = this.client.pbkdf2Sync(
      password,
      salt,
      rec.iterations,
      rec.dkLen,
      "sha256"
    );
    const stored = Buffer.from(rec.hashB64, "base64");
    if (stored.length !== hash.length) return false;
    return this.client.timingSafeEqual(stored, hash);
  }
}
