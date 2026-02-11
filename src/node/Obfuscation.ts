import zlib from "zlib";
import { Crypto } from "./Crypto";

const MAGIC = Buffer.from("DECAF1", "ascii");
const SALT_BYTES = 16;
const IV_BYTES = 12;
const TAG_BYTES = 16;

export class Obfuscation {
  private constructor() {}

  static getKeyMaterial() {
    return process.env.ENCRYPTION_KEY || "";
  }

  static deriveKey(keyMaterial: string, salt: Buffer) {
    return Crypto.scryptSync(keyMaterial, salt, 32);
  }

  static obfuscate(secret: string, input: Buffer) {
    const salt = Crypto.randomBytes(SALT_BYTES);
    const iv = Crypto.randomBytes(IV_BYTES);
    const key = this.deriveKey(secret, salt);
    const gzipped = zlib.gzipSync(input, { level: 9 });
    const cipher = Crypto.createCipheriv("aes-256-gcm", key, iv);
    const ciphertext = Buffer.concat([cipher.update(gzipped), cipher.final()]);
    const tag = cipher.getAuthTag();

    return Buffer.concat([MAGIC, salt, iv, tag, ciphertext]);
  }

  static deobfuscate(secret: string, input: Buffer) {
    if (input.length < MAGIC.length + SALT_BYTES + IV_BYTES + TAG_BYTES) {
      throw new Error("Invalid prompt payload (too short)");
    }
    const magic = input.subarray(0, MAGIC.length);
    if (!magic.equals(MAGIC)) {
      throw new Error("Invalid prompt payload (bad magic)");
    }

    let offset = MAGIC.length;
    const salt = input.subarray(offset, offset + SALT_BYTES);
    offset += SALT_BYTES;
    const iv = input.subarray(offset, offset + IV_BYTES);
    offset += IV_BYTES;
    const tag = input.subarray(offset, offset + TAG_BYTES);
    offset += TAG_BYTES;
    const ciphertext = input.subarray(offset);

    const key = this.deriveKey(secret, salt);
    const decipher = Crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);
    return zlib.gunzipSync(plaintext);
  }
}
