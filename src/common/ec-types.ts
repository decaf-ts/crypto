import { Algorithm, AlgorithmIdentifier } from "./util-types";
import { CryptoKey } from "jose";

export interface EcKeyAlgorithm extends Algorithm {
  namedCurve: string;
}

export interface EcKeyGenParams extends Algorithm {
  namedCurve: string;
}

export interface EcKeyImportParams extends Algorithm {
  namedCurve: string;
}

export interface EcdsaParams extends Algorithm {
  hash: AlgorithmIdentifier;
}

export interface EcdhKeyDeriveParams extends Algorithm {
  public: CryptoKey;
}

export type NamedCurve = "P-256" | "P-384" | "P-521" | "X25519" | "Ed25519";
