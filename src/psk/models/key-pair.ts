/**
 * @description Represents a key pair with private and public keys as strings.
 * @interface KeyPair
 * @property {string} privateKey - The private key, typically in PEM format.
 * @property {string} publicKey - The public key, typically in PEM format.
 * @memberOf module:@decaf-ts/crypto/psk
 */
export interface KeyPair {
  privateKey: string;
  publicKey: string;
}
