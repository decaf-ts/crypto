import { Algorithm, AlgorithmIdentifier } from "./util-types";

export interface HmacKeyAlgorithm extends Algorithm {
  hash: AlgorithmIdentifier;
  length: number;
}

export interface HmacImportParams extends Algorithm {
  hash: AlgorithmIdentifier;
  length?: number;
}

export interface HmacKeyGenParams extends Algorithm {
  hash: AlgorithmIdentifier;
  length?: number;
}
