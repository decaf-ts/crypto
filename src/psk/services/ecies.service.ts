import crypto from 'crypto';
import { BufferLike, toBuffer } from '../utils/encoding';
import { EciesEnvelope, EciesOptions } from '../models/ecies';

const DEFAULT_OPTIONS: Required<EciesOptions> = {
  curve: 'secp256k1',
  encodingFormat: 'base64',
  symmetricKeySize: 16,
  macKeySize: 16,
};

/**
 * @description A service for ECIES (Elliptic Curve Integrated Encryption Scheme) encryption and decryption.
 * @summary This service provides methods to encrypt and decrypt data using ECIES. It uses ECDH for key agreement, HKDF for key derivation, AES-128-CBC for symmetric encryption, and HMAC-SHA256 for authentication.
 * @class PskEciesService
 * @memberOf module:@decaf-ts/crypto/psk
 */
export class PskEciesService {

  /**
   * @description Encrypts a message for a recipient using their public key.
   * @summary This method generates an ephemeral key pair, derives a shared secret using ECDH with the recipient's public key, and then encrypts the message using AES-128-CBC. It also computes an HMAC tag for integrity.
   * @param {BufferLike | string | crypto.KeyObject} receiverPublicKey - The recipient's public key.
   * @param {BufferLike} message - The message to encrypt.
   * @param {EciesOptions} [options={}] - Optional configuration for the encryption process.
   * @returns {EciesEnvelope} An object containing the encrypted message and associated metadata (ephemeral public key, IV, tag, etc.).
   * @function encrypt
   * @memberOf module:@decaf-ts/crypto/psk
   */
  encrypt(
    receiverPublicKey: BufferLike | string | crypto.KeyObject,
    message: BufferLike,
    options: EciesOptions = {}
  ): EciesEnvelope {
    const opts = { ...DEFAULT_OPTIONS, ...options };

    const receiverKeyObject = this.toPublicKeyObject(receiverPublicKey);
    const messageBuffer = toBuffer(message);

    const ephemeral = crypto.generateKeyPairSync('ec', { namedCurve: opts.curve });

    const sharedSecret = crypto.diffieHellman({
      privateKey: ephemeral.privateKey,
      publicKey: receiverKeyObject,
    });
    const { symmetricKey, macKey } = this.deriveKeys(sharedSecret, opts);

    const iv = crypto.randomBytes(opts.symmetricKeySize);
    const cipher = crypto.createCipheriv('aes-128-cbc', symmetricKey, iv);
    const ciphertext = Buffer.concat([cipher.update(messageBuffer), cipher.final()]);

    const tag = crypto.createHmac('sha256', macKey).update(Buffer.concat([ciphertext, iv])).digest();

    return {
      to_ecdh: this.encode(receiverKeyObject.export({ format: 'der', type: 'spki' }), opts.encodingFormat),
      r: this.encode(ephemeral.publicKey.export({ format: 'der', type: 'spki' }), opts.encodingFormat),
      ct: this.encode(ciphertext, opts.encodingFormat),
      iv: this.encode(iv, opts.encodingFormat),
      tag: this.encode(tag, opts.encodingFormat),
    };
  }

  /**
   * @description Decrypts an ECIES envelope using the recipient's private key.
   * @summary This method derives the shared secret using the recipient's private key and the ephemeral public key from the envelope. It then verifies the HMAC tag and decrypts the ciphertext using AES-128-CBC.
   * @param {BufferLike | string | crypto.KeyObject} receiverPrivateKey - The recipient's private key.
   * @param {EciesEnvelope} envelope - The ECIES envelope containing the encrypted message and metadata.
   * @param {EciesOptions} [options={}] - Optional configuration for the decryption process.
   * @returns {Buffer} The decrypted message as a Buffer.
   * @throws {Error} If the MAC verification fails.
   * @function decrypt
   * @memberOf module:@decaf-ts/crypto/psk
   */
  decrypt(
    receiverPrivateKey: BufferLike | string | crypto.KeyObject,
    envelope: EciesEnvelope,
    options: EciesOptions = {}
  ): Buffer {
    const opts = { ...DEFAULT_OPTIONS, ...options };

    const privateKey = this.toPrivateKeyObject(receiverPrivateKey);
    const ephemeralPublicKeyObject = crypto.createPublicKey({
      key: this.decode(envelope.r, opts.encodingFormat),
      format: 'der',
      type: 'spki',
    });

    const sharedSecret = crypto.diffieHellman({
      privateKey,
      publicKey: ephemeralPublicKeyObject,
    });
    const { symmetricKey, macKey } = this.deriveKeys(sharedSecret, opts);

    const ciphertext = this.decode(envelope.ct, opts.encodingFormat);
    const iv = this.decode(envelope.iv, opts.encodingFormat);
    const tag = this.decode(envelope.tag, opts.encodingFormat);

    const expectedTag = crypto.createHmac('sha256', macKey)
      .update(Buffer.concat([ciphertext, iv]))
      .digest();

    if (!crypto.timingSafeEqual(expectedTag, tag)) {
      throw new Error('Bad MAC');
    }

    const decipher = crypto.createDecipheriv('aes-128-cbc', symmetricKey, iv);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }

  /**
   * @description Derives symmetric and MAC keys from a shared secret.
   * @summary This private helper method uses HKDF with SHA-256 to derive the keys needed for encryption and authentication.
   * @param {Buffer} sharedSecret - The shared secret derived from ECDH.
   * @param {Required<EciesOptions>} options - The options containing key sizes.
   * @returns {{ symmetricKey: Buffer; macKey: Buffer }} An object containing the derived symmetric and MAC keys.
   * @function deriveKeys
   * @memberOf module:@decaf-ts/crypto/psk
   */
  private deriveKeys(sharedSecret: Buffer, options: Required<EciesOptions>) {
    const totalSize = options.symmetricKeySize + options.macKeySize;
    const derived = Buffer.from(crypto.hkdfSync('sha256', sharedSecret, Buffer.alloc(0), 'psk-ecies', totalSize));
    return {
      symmetricKey: derived.slice(0, options.symmetricKeySize),
      macKey: derived.slice(options.symmetricKeySize, totalSize),
    };
  }

  /**
   * @description Converts a public key input to a `KeyObject`.
   * @summary This private helper method handles the conversion logic for public keys.
   * @param {BufferLike | string | crypto.KeyObject} value - The public key input.
   * @returns {crypto.KeyObject} The public key object.
   * @function toPublicKeyObject
   * @memberOf module:@decaf-ts/crypto/psk
   */
  private toPublicKeyObject(value: BufferLike | string | crypto.KeyObject): crypto.KeyObject {
    if (value instanceof crypto.KeyObject) {
      return value;
    }
    if (typeof value === 'string') {
      return crypto.createPublicKey(value);
    }
    return crypto.createPublicKey({ key: toBuffer(value), format: 'der', type: 'spki' });
  }

  /**
   * @description Converts a private key input to a `KeyObject`.
   * @summary This private helper method handles the conversion logic for private keys.
   * @param {BufferLike | string | crypto.KeyObject} value - The private key input.
   * @returns {crypto.KeyObject} The private key object.
   * @function toPrivateKeyObject
   * @memberOf module:@decaf-ts/crypto/psk
   */
  private toPrivateKeyObject(value: BufferLike | string | crypto.KeyObject): crypto.KeyObject {
    if (value instanceof crypto.KeyObject) {
      return value;
    }
    if (typeof value === 'string') {
      return crypto.createPrivateKey(value);
    }
    return crypto.createPrivateKey({ key: toBuffer(value), format: 'der', type: 'sec1' });
  }

  /**
   * @description Encodes a buffer to a string using the specified format.
   * @summary This private helper method encodes a buffer to 'base64' or 'hex'.
   * @param {Buffer} value - The buffer to encode.
   * @param {Required<EciesOptions>['encodingFormat']} encoding - The encoding format.
   * @returns {string} The encoded string.
   * @function encode
   * @memberOf module:@decaf-ts/crypto/psk
   */
  private encode(value: Buffer, encoding: Required<EciesOptions>['encodingFormat']): string {
    return value.toString(encoding);
  }

  /**
   * @description Decodes a string to a buffer using the specified format.
   * @summary This private helper method decodes a 'base64' or 'hex' string to a buffer.
   * @param {string} value - The string to decode.
   * @param {Required<EciesOptions>['encodingFormat']} encoding - The encoding format.
   * @returns {Buffer} The decoded buffer.
   * @function decode
   * @memberOf module:@decaf-ts/crypto/psk
   */
  private decode(value: string, encoding: Required<EciesOptions>['encodingFormat']): Buffer {
    return Buffer.from(value, encoding);
  }
}
