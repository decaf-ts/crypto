/**
 * @description Represents the encoding format for ECIES operations.
 * @typedef {'base64' | 'hex'} EncodingFormat
 * @memberOf module:@decaf-ts/crypto/psk
 */
export type EncodingFormat = 'base64' | 'hex';

/**
 * @description Represents an ECIES encrypted envelope.
 * @interface EciesEnvelope
 * @property {string} to_ecdh - The recipient's ECDH public key.
 * @property {string} r - The ephemeral public key.
 * @property {string} ct - The ciphertext.
 * @property {string} iv - The initialization vector.
 * @property {string} tag - The MAC tag.
 * @memberOf module:@decaf-ts/crypto/psk
 */
export interface EciesEnvelope {
  to_ecdh: string;
  r: string;
  ct: string;
  iv: string;
  tag: string;
}

/**
 * @description Represents options for ECIES operations.
 * @interface EciesOptions
 * @property {EncodingFormat} [encodingFormat] - The encoding format for the envelope fields.
 * @property {string} [curve] - The elliptic curve to use.
 * @property {number} [symmetricKeySize] - The size of the symmetric key in bytes.
 * @property {number} [macKeySize] - The size of the MAC key in bytes.
 * @memberOf module:@decaf-ts/crypto/psk
 */
export interface EciesOptions {
  encodingFormat?: EncodingFormat;
  curve?: string;
  symmetricKeySize?: number;
  macKeySize?: number;
}
