/**
 * @module @decaf-ts/crypto/psk
 * @description
 * This module provides a set of services for cryptographic operations, including ECIES, JOSE, and JWT.
 * @summary
 * This module exports the following services:
 * - {@link module:@decaf-ts/crypto/psk.PskCryptoService|PskCryptoService}: A service for various cryptographic utilities.
 * - {@link module:@decaf-ts/crypto/psk.PskEciesService|PskEciesService}: A service for ECIES encryption and decryption.
 * - {@link module:@decaf-ts/crypto/psk.PskJoseService|PskJoseService}: A service for JOSE (JWS/JWE) operations.
 * - {@link module:@decaf-ts/crypto/psk.PskJwtService|PskJwtService}: A service for JWT operations.
 * - {@link module:@decaf-ts/crypto/psk.PskMutualAuthEciesService|PskMutualAuthEciesService}: A service for mutual authentication ECIES.
 *
 * It also exports the {@link module:@decaf-ts/crypto/psk.PskKeyLike|PskKeyLike} type.
 */
import { PskCryptoService } from './services/psk-crypto.service';
import { PskEciesService } from './services/ecies.service';
import { PskJoseService } from './services/jose.service';
import { PskJwtService } from './services/jwt.service';
import { PskMutualAuthEciesService } from './services/ecies-mutual-auth.service';
import type { PskKeyLike } from './services/psk-crypto.service';

const pskCrypto = new PskCryptoService();
const pskEcies = new PskEciesService();
const pskJose = new PskJoseService();
const pskJwt = new PskJwtService();
const pskMutualAuth = new PskMutualAuthEciesService();

export { PskCryptoService, PskEciesService, PskJoseService, PskJwtService, PskMutualAuthEciesService };
export type { PskKeyLike };
export default pskCrypto;
export { pskEcies, pskJose, pskJwt, pskMutualAuth };
