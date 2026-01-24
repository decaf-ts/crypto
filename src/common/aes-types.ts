import { Algorithm, BufferSource } from "./util-types";

export interface AesKeyAlgorithm extends Algorithm {
  length: number;
}

export interface AesKeyGenParams extends Algorithm {
  length: number;
}

export interface AesCbcParams extends Algorithm {
  iv: BufferSource;
}

export interface AesCtrParams extends Algorithm {
  counter: BufferSource;
  length: number;
}

export interface AesGcmParams extends Algorithm {
  iv: BufferSource;
  additionalData?: BufferSource;
  tagLength?: number;
}

export interface AesDerivedKeyParams extends Algorithm {
  length: number;
}
