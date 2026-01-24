export interface Algorithm {
  name: string;
}

export interface HashAlgorithm extends Algorithm {}

export type AlgorithmIdentifier = string | Algorithm;

export type BufferSource = ArrayBuffer | ArrayBufferView;

export type KeyFormat = "raw" | "pkcs8" | "spki" | "jwk";

export type KeyType = "public" | "private" | "secret";

export type KeyUsage =
  | "encrypt"
  | "decrypt"
  | "sign"
  | "verify"
  | "deriveKey"
  | "deriveBits"
  | "wrapKey"
  | "unwrapKey";
