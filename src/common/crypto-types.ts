import {
  Algorithm,
  AlgorithmIdentifier,
  KeyType,
  KeyUsage,
} from "./util-types";

export interface CryptoKey {
  readonly type: KeyType;
  readonly extractable: boolean;
  readonly algorithm: Algorithm;
  readonly usages: readonly KeyUsage[];
}

export interface CryptoKeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

export interface JsonWebKey {
  kty?: string;
  use?: string;
  key_ops?: string[];
  alg?: string;

  // RSA
  n?: string;
  e?: string;
  d?: string;
  p?: string;
  q?: string;
  dp?: string;
  dq?: string;
  qi?: string;

  // EC
  crv?: string;
  x?: string;
  y?: string;

  // Symmetric
  k?: string;

  ext?: boolean;
}
