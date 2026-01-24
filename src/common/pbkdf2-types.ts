import { Algorithm, AlgorithmIdentifier, BufferSource } from "./util-types";

export interface Pbkdf2Params extends Algorithm {
  salt: BufferSource;
  iterations: number;
  hash: AlgorithmIdentifier;
}

export interface HkdfParams extends Algorithm {
  hash: AlgorithmIdentifier;
  salt: BufferSource;
  info: BufferSource;
}
