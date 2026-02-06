import { SubtleCrypto } from "./Subtle";
import { KeyUsage } from "./util-types";
import { CryptoKey } from "./crypto-types";
import { AesGcmParams } from "./aes-types";

export function arrayBufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function hexToArrayBuffer(hexString: string): ArrayBuffer {
  const bytes = new Uint8Array(hexString.length / 2);
  for (let i = 0; i < hexString.length; i += 2) {
    bytes[i / 2] = parseInt(hexString.substring(i, i + 2), 16);
  }
  return bytes.buffer;
}

export async function getDerivedKey(
  subtle: SubtleCrypto,
  secret: string,
  algorithmName: string, // Changed to string for CLI input
  keyLength: number,
  keyUsages: KeyUsage[]
): Promise<CryptoKey> {
  const keyMaterial = new TextEncoder().encode(secret);
  return subtle.importKey(
    "raw",
    keyMaterial,
    { name: algorithmName, length: keyLength }, // Construct AlgorithmIdentifier
    true, // extractable
    keyUsages
  );
}

export async function encryptContent(
  subtle: SubtleCrypto,
  key: CryptoKey,
  algorithmName: string,
  plainText: string
): Promise<string> {
  const encodedData = new TextEncoder().encode(plainText);
  const iv = crypto.getRandomValues(new Uint8Array(12)); // Generate a random IV for AES-GCM

  const algorithm: AesGcmParams = { name: algorithmName, iv: iv };

  const encryptedData = await subtle.encrypt(algorithm, key, encodedData);
  const combined = new Uint8Array(iv.byteLength + encryptedData.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encryptedData), iv.byteLength);
  return arrayBufferToHex(combined.buffer);
}

export async function decryptContent(
  subtle: SubtleCrypto,
  key: CryptoKey,
  algorithmName: string,
  encryptedHex: string
): Promise<string> {
  const combinedBuffer = hexToArrayBuffer(encryptedHex);
  // Assuming IV length is 12 bytes
  const iv = new Uint8Array(combinedBuffer, 0, 12);
  const encryptedData = new Uint8Array(combinedBuffer, 12);

  const algorithm: AesGcmParams = { name: algorithmName, iv: iv };

  const decryptedData = await subtle.decrypt(algorithm, key, encryptedData);
  return new TextDecoder().decode(decryptedData);
}
