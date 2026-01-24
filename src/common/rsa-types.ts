import { Algorithm, AlgorithmIdentifier, BufferSource } from "./util-types";

export interface RsaKeyAlgorithm extends Algorithm {
  modulusLength: number;
  publicExponent: Uint8Array;
}

export interface RsaHashedKeyAlgorithm extends RsaKeyAlgorithm {
  hash: AlgorithmIdentifier;
}

export interface RsaHashedKeyGenParams extends RsaKeyAlgorithm {
  hash: AlgorithmIdentifier;
}

export interface RsaHashedImportParams extends Algorithm {
  hash: AlgorithmIdentifier;
}

export interface RsaOaepParams extends Algorithm {
  label?: BufferSource;
}

export interface RsaPssParams extends Algorithm {
  saltLength: number;
}
