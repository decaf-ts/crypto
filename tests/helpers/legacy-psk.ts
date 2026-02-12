import { Buffer } from 'node:buffer';

const DOLLAR = String.fromCharCode(36);
const LEGACY_GLOBAL_KEY = `${DOLLAR}${DOLLAR}`;

type LegacyGlobal = {
  Buffer: typeof Buffer;
  environmentType?: string;
};

const legacyGlobal = (globalThis as Record<string, unknown>)[LEGACY_GLOBAL_KEY] as LegacyGlobal | undefined;

if (!legacyGlobal) {
  Object.defineProperty(globalThis, LEGACY_GLOBAL_KEY, {
    value: {
      Buffer,
      environmentType: 'node',
    },
    configurable: true,
    writable: true,
  });
} else {
  legacyGlobal.Buffer = Buffer;
  if (!legacyGlobal.environmentType) {
    legacyGlobal.environmentType = 'node';
  }
}

// eslint-disable-next-line @typescript-eslint/no-require-imports
const LegacyPskCrypto = require('../../psk-crypto') as LegacyPskCryptoInstance & {
  hashValues: (values: unknown) => string;
};

type LegacyPskCryptoInstance = {
  pskHash(data: Buffer | string | object): Buffer;
  hash(algorithm: string, data: Buffer | string, encoding?: BufferEncoding): Buffer;
  objectHash(algorithm: string, data: Record<string, unknown>, encoding?: BufferEncoding): Buffer;
  pskBase58Encode(data: Buffer): string;
  pskBase58Decode(data: string): Buffer;
  pskBase64Encode(data: Buffer): string;
  pskBase64Decode(data: string): Buffer;
  generateSafeUid(password?: Buffer, additionalData?: Buffer): string;
  deriveKey(algorithm: string, password: Buffer, iterations: number): Buffer;
  xorBuffers(...buffers: Buffer[]): Buffer;
  pskHashStream(stream: NodeJS.ReadableStream, callback: (err: Error | null, hash?: Buffer) => void): void;
};

const legacyPskCrypto = LegacyPskCrypto;

export { legacyPskCrypto };
export const legacyHashValues = LegacyPskCrypto.hashValues;
