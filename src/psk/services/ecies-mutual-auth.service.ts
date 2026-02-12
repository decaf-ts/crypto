import crypto from 'crypto';
import { BufferLike, toBuffer } from '../utils/encoding';
import { EciesEnvelope, EciesOptions } from '../models/ecies';
import { PskEciesService } from './ecies.service';

interface KeyBufferParams {
  symmetricCipherKey: Buffer;
  ciphertextMacKey: Buffer;
  recvsMacKey: Buffer;
}

/**
 * @description Represents an encrypted envelope for a group of recipients.
 * @interface GroupEncryptedEnvelope
 * @property {string} recvs - The encrypted list of recipient envelopes.
 * @property {string} rtag - The MAC tag for the recipients list.
 * @property {string} ct - The ciphertext.
 * @property {string} iv - The initialization vector.
 * @property {string} tag - The MAC tag for the ciphertext.
 * @memberOf module:@decaf-ts/crypto/psk
 */
interface GroupEncryptedEnvelope {
  recvs: string;
  rtag: string;
  ct: string;
  iv: string;
  tag: string;
}

const DEFAULT_OPTIONS: Required<EciesOptions> = {
  curve: 'secp256k1',
  encodingFormat: 'base64',
  symmetricKeySize: 16,
  macKeySize: 16,
};

/**
 * @description Represents a key pair used for signing in ECIES.
 * @interface EciesSigningKeyPair
 * @property {crypto.KeyObject} publicKey - The public key.
 * @property {crypto.KeyObject} privateKey - The private key.
 * @memberOf module:@decaf-ts/crypto/psk
 */
export interface EciesSigningKeyPair {
  publicKey: crypto.KeyObject;
  privateKey: crypto.KeyObject;
}

/**
 * @description A service for ECIES with mutual authentication and group encryption.
 * @summary This service extends the capabilities of `PskEciesService` to support mutual authentication (using digital signatures) and group encryption (encrypting for multiple recipients).
 * @class PskMutualAuthEciesService
 * @memberOf module:@decaf-ts/crypto/psk
 */
export class PskMutualAuthEciesService {
  private readonly ecies = new PskEciesService();

  /**
   * @description Encrypts a message for a recipient using ECIES.
   * @summary This method delegates to `PskEciesService.encrypt`.
   * @param {BufferLike | string | crypto.KeyObject} receiverPublicKey - The recipient's public key.
   * @param {BufferLike} message - The message to encrypt.
   * @param {EciesOptions} [options={}] - Optional configuration.
   * @returns {EciesEnvelope} The encrypted envelope.
   * @function encrypt
   * @memberOf module:@decaf-ts/crypto/psk
   */
  encrypt(
    receiverPublicKey: BufferLike | string | crypto.KeyObject,
    message: BufferLike,
    options: EciesOptions = {}
  ): EciesEnvelope {
    return this.ecies.encrypt(receiverPublicKey, message, options);
  }

  /**
   * @description Decrypts an ECIES envelope.
   * @summary This method delegates to `PskEciesService.decrypt`.
   * @param {BufferLike | string | crypto.KeyObject} receiverPrivateKey - The recipient's private key.
   * @param {EciesEnvelope} envelope - The encrypted envelope.
   * @param {EciesOptions} [options={}] - Optional configuration.
   * @returns {Buffer} The decrypted message.
   * @function decrypt
   * @memberOf module:@decaf-ts/crypto/psk
   */
  decrypt(
    receiverPrivateKey: BufferLike | string | crypto.KeyObject,
    envelope: EciesEnvelope,
    options: EciesOptions = {}
  ): Buffer {
    return this.ecies.decrypt(receiverPrivateKey, envelope, options);
  }

  /**
   * @description Encrypts a message with digital signature (mutual authentication).
   * @summary This method signs the message with the sender's private key, wraps the message and signature, and then encrypts it for the recipient.
   * @param {EciesSigningKeyPair} senderKeyPair - The sender's key pair for signing.
   * @param {BufferLike | string | crypto.KeyObject} receiverPublicKey - The recipient's public key.
   * @param {BufferLike} message - The message to encrypt.
   * @param {EciesOptions} [options={}] - Optional configuration.
   * @returns {EciesEnvelope} The encrypted envelope.
   * @function encrypt_ds
   * @memberOf module:@decaf-ts/crypto/psk
   */
  encrypt_ds(
    senderKeyPair: EciesSigningKeyPair,
    receiverPublicKey: BufferLike | string | crypto.KeyObject,
    message: BufferLike,
    options: EciesOptions = {}
  ): EciesEnvelope {
    const payload = this.wrapSignedPayload(message, senderKeyPair);
    return this.ecies.encrypt(receiverPublicKey, payload, options);
  }

  /**
   * @description Decrypts a message with digital signature verification.
   * @summary This method decrypts the envelope, parses the payload to extract the message and signature, and verifies the signature using the sender's public key (included in the payload).
   * @param {BufferLike | string | crypto.KeyObject} receiverPrivateKey - The recipient's private key.
   * @param {EciesEnvelope} envelope - The encrypted envelope.
   * @param {EciesOptions} [options={}] - Optional configuration.
   * @returns {{ from_ecsig: crypto.KeyObject; message: Buffer }} An object containing the sender's public key and the decrypted message.
   * @throws {Error} If the signature verification fails.
   * @function decrypt_ds
   * @memberOf module:@decaf-ts/crypto/psk
   */
  decrypt_ds(
    receiverPrivateKey: BufferLike | string | crypto.KeyObject,
    envelope: EciesEnvelope,
    options: EciesOptions = {}
  ) {
    const decrypted = this.ecies.decrypt(receiverPrivateKey, envelope, options);
    const parsed = JSON.parse(decrypted.toString('utf8')) as {
      from_ecsig: string;
      msg: string;
      sig: string;
    };
    const senderPublic = crypto.createPublicKey(parsed.from_ecsig);
    const message = Buffer.from(parsed.msg, 'base64');
    const signature = Buffer.from(parsed.sig, 'base64');
    if (!crypto.verify('sha256', message, senderPublic, signature)) {
      throw new Error('Bad signature');
    }
    return {
      from_ecsig: senderPublic,
      message,
    };
  }

  /**
   * @description Encrypts a message using Keyed-MAC (KMAC).
   * @summary This is an alias for `encrypt`.
   * @param {BufferLike | string | crypto.KeyObject} receiverPublicKey - The recipient's public key.
   * @param {BufferLike} message - The message to encrypt.
   * @param {EciesOptions} [options={}] - Optional configuration.
   * @returns {EciesEnvelope} The encrypted envelope.
   * @function encrypt_kmac
   * @memberOf module:@decaf-ts/crypto/psk
   */
  encrypt_kmac(
    receiverPublicKey: BufferLike | string | crypto.KeyObject,
    message: BufferLike,
    options: EciesOptions = {}
  ) {
    return this.encrypt(receiverPublicKey, message, options);
  }

  /**
   * @description Decrypts a message using Keyed-MAC (KMAC).
   * @summary This is an alias for `decrypt`.
   * @param {BufferLike | string | crypto.KeyObject} receiverPrivateKey - The recipient's private key.
   * @param {EciesEnvelope} envelope - The encrypted envelope.
   * @param {EciesOptions} [options={}] - Optional configuration.
   * @returns {Buffer} The decrypted message.
   * @function decrypt_kmac
   * @memberOf module:@decaf-ts/crypto/psk
   */
  decrypt_kmac(
    receiverPrivateKey: BufferLike | string | crypto.KeyObject,
    envelope: EciesEnvelope,
    options: EciesOptions = {}
  ) {
    return this.decrypt(receiverPrivateKey, envelope, options);
  }

  /**
   * @description Encrypts a message for a group of recipients.
   * @summary This method generates a symmetric key and MAC keys, encrypts the message with the symmetric key, and then encrypts the keys for each recipient using ECIES.
   * @param {BufferLike} message - The message to encrypt.
   * @param {(crypto.KeyObject | BufferLike | string)[]} receivers - An array of recipients' public keys.
   * @param {EciesOptions} [options={}] - Optional configuration.
   * @returns {GroupEncryptedEnvelope} The group encrypted envelope.
   * @function encrypt_group
   * @memberOf module:@decaf-ts/crypto/psk
   */
  encrypt_group(message: BufferLike, receivers: (crypto.KeyObject | BufferLike | string)[], options: EciesOptions = {}): GroupEncryptedEnvelope {
    const opts = { ...DEFAULT_OPTIONS, ...options };
    const keyBufferParams = this.generateKeyBufferParams(opts);
    const keyBuffer = Buffer.concat([
      keyBufferParams.symmetricCipherKey,
      keyBufferParams.ciphertextMacKey,
      keyBufferParams.recvsMacKey,
    ]);
    const recvsBuffer = this.multiRecipientEncrypt(keyBuffer, receivers, opts);
    const iv = crypto.randomBytes(opts.symmetricKeySize);
    const ciphertext = this.symmetricEncrypt(keyBufferParams.symmetricCipherKey, toBuffer(message), iv);
    const tag = this.computeMac(keyBufferParams.ciphertextMacKey, ciphertext, iv);
    const recvsTag = this.computeMac(keyBufferParams.recvsMacKey, recvsBuffer, Buffer.alloc(0));
    return {
      recvs: recvsBuffer.toString(opts.encodingFormat),
      rtag: recvsTag.toString(opts.encodingFormat),
      ct: ciphertext.toString(opts.encodingFormat),
      iv: iv.toString(opts.encodingFormat),
      tag: tag.toString(opts.encodingFormat),
    };
  }

  /**
   * @description Decrypts a group encrypted message.
   * @summary This method finds the recipient's encrypted key envelope in the `recvs` list, decrypts it to get the symmetric keys, and then decrypts the message.
   * @param {crypto.KeyObject | BufferLike | string} receiverPrivateKey - The recipient's private key.
   * @param {GroupEncryptedEnvelope} envelope - The group encrypted envelope.
   * @param {EciesOptions} [options={}] - Optional configuration.
   * @returns {Buffer} The decrypted message.
   * @throws {Error} If MAC verification fails.
   * @function decrypt_group
   * @memberOf module:@decaf-ts/crypto/psk
   */
  decrypt_group(
    receiverPrivateKey: crypto.KeyObject | BufferLike | string,
    envelope: GroupEncryptedEnvelope,
    options: EciesOptions = {}
  ): Buffer {
    const opts = { ...DEFAULT_OPTIONS, ...options };
    const keyBuffer = this.multiRecipientDecrypt(receiverPrivateKey, envelope.recvs, opts);
    const parsedKeys = this.parseKeyBuffer(keyBuffer, opts);
    const ciphertext = Buffer.from(envelope.ct, opts.encodingFormat);
    const iv = Buffer.from(envelope.iv, opts.encodingFormat);
    const tag = Buffer.from(envelope.tag, opts.encodingFormat);
    const expectedTag = this.computeMac(parsedKeys.ciphertextMacKey, ciphertext, iv);
    if (!crypto.timingSafeEqual(expectedTag, tag)) {
      throw new Error('Bad MAC');
    }
    const expectedRecvsTag = this.computeMac(parsedKeys.recvsMacKey, Buffer.from(envelope.recvs, opts.encodingFormat), Buffer.alloc(0));
    if (!crypto.timingSafeEqual(expectedRecvsTag, Buffer.from(envelope.rtag, opts.encodingFormat))) {
      throw new Error('Bad recipients MAC');
    }
    return this.symmetricDecrypt(parsedKeys.symmetricCipherKey, ciphertext, iv);
  }

  /**
   * @description Encrypts a message for a group of recipients with digital signature.
   * @summary This method combines `encrypt_ds` logic with `encrypt_group`. It signs the message and then encrypts the signed payload for the group.
   * @param {EciesSigningKeyPair} senderKeyPair - The sender's key pair for signing.
   * @param {(crypto.KeyObject | BufferLike | string)[]} receivers - An array of recipients' public keys.
   * @param {BufferLike} message - The message to encrypt.
   * @param {EciesOptions} [options={}] - Optional configuration.
   * @returns {GroupEncryptedEnvelope} The group encrypted envelope.
   * @function encrypt_group_ds
   * @memberOf module:@decaf-ts/crypto/psk
   */
  encrypt_group_ds(
    senderKeyPair: EciesSigningKeyPair,
    receivers: (crypto.KeyObject | BufferLike | string)[],
    message: BufferLike,
    options: EciesOptions = {}
  ): GroupEncryptedEnvelope {
    const wrapped = this.wrapSignedPayload(message, senderKeyPair);
    return this.encrypt_group(wrapped, receivers, options);
  }

  /**
   * @description Decrypts a group encrypted message with digital signature verification.
   * @summary This method decrypts the group envelope and then verifies the signature of the payload.
   * @param {crypto.KeyObject | BufferLike | string} receiverPrivateKey - The recipient's private key.
   * @param {GroupEncryptedEnvelope} envelope - The group encrypted envelope.
   * @param {EciesOptions} [options={}] - Optional configuration.
   * @returns {{ from_ecsig: crypto.KeyObject; message: Buffer }} An object containing the sender's public key and the decrypted message.
   * @throws {Error} If signature verification fails.
   * @function decrypt_group_ds
   * @memberOf module:@decaf-ts/crypto/psk
   */
  decrypt_group_ds(
    receiverPrivateKey: crypto.KeyObject | BufferLike | string,
    envelope: GroupEncryptedEnvelope,
    options: EciesOptions = {}
  ) {
    const decrypted = this.decrypt_group(receiverPrivateKey, envelope, options);
    const parsed = JSON.parse(decrypted.toString('utf8')) as {
      from_ecsig: string;
      msg: string;
      sig: string;
    };
    const senderPublic = crypto.createPublicKey(parsed.from_ecsig);
    const message = Buffer.from(parsed.msg, 'base64');
    const signature = Buffer.from(parsed.sig, 'base64');
    if (!crypto.verify('sha256', message, senderPublic, signature)) {
      throw new Error('Bad signature');
    }
    return {
      from_ecsig: senderPublic,
      message,
    };
  }

  /**
   * @description Extracts the ECDH public key from an ECIES envelope.
   * @summary This method decodes the `to_ecdh` field of the envelope and creates a `KeyObject`.
   * @param {EciesEnvelope} envelope - The ECIES envelope.
   * @returns {crypto.KeyObject} The ECDH public key.
   * @function ecies_getDecodedECDHPublicKeyFromEncEnvelope
   * @memberOf module:@decaf-ts/crypto/psk
   */
  ecies_getDecodedECDHPublicKeyFromEncEnvelope(envelope: EciesEnvelope): crypto.KeyObject {
    return crypto.createPublicKey({
      key: Buffer.from(envelope.to_ecdh, DEFAULT_OPTIONS.encodingFormat),
      format: 'der',
      type: 'spki',
    });
  }

  /**
   * @description Extracts recipient ECDH public keys from a group encrypted envelope.
   * @summary This method parses the `recvs` field of the group envelope and extracts the ECDH public keys for all recipients.
   * @param {GroupEncryptedEnvelope} envelope - The group encrypted envelope.
   * @returns {crypto.KeyObject[]} An array of ECDH public keys.
   * @throws {Error} If the `recvs` field is missing.
   * @function ecies_group_getRecipientECDHPublicKeysFromEncEnvelope
   * @memberOf module:@decaf-ts/crypto/psk
   */
  ecies_group_getRecipientECDHPublicKeysFromEncEnvelope(envelope: GroupEncryptedEnvelope): crypto.KeyObject[] {
    const opts = DEFAULT_OPTIONS;
    if (!envelope.recvs) {
      throw new Error('Missing recvs field');
    }
    const recvsBuffer = Buffer.from(envelope.recvs, opts.encodingFormat);
    const arr = JSON.parse(recvsBuffer.toString('utf8')) as EciesEnvelope[];
    return arr.map((cur) => this.ecies_getDecodedECDHPublicKeyFromEncEnvelope(cur));
  }

  private wrapSignedPayload(message: BufferLike, senderKeyPair: EciesSigningKeyPair): Buffer {
    const payload = {
      from_ecsig: senderKeyPair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      msg: toBuffer(message).toString('base64'),
      sig: crypto
        .sign('sha256', toBuffer(message), senderKeyPair.privateKey)
        .toString('base64'),
    };
    return Buffer.from(JSON.stringify(payload), 'utf8');
  }

  private generateKeyBufferParams(options: Required<EciesOptions>): KeyBufferParams {
    return {
      symmetricCipherKey: crypto.randomBytes(options.symmetricKeySize),
      ciphertextMacKey: crypto.randomBytes(options.macKeySize),
      recvsMacKey: crypto.randomBytes(options.macKeySize),
    };
  }

  private multiRecipientEncrypt(
    keyBuffer: Buffer,
    receivers: (crypto.KeyObject | BufferLike | string)[],
    options: Required<EciesOptions>
  ): Buffer {
    const arr = receivers.map((receiver) =>
      this.ecies.encrypt(receiver, keyBuffer, options)
    );
    return Buffer.from(JSON.stringify(arr), 'utf8');
  }

  private multiRecipientDecrypt(
    receiverPrivateKey: crypto.KeyObject | BufferLike | string,
    recvs: string,
    options: Required<EciesOptions>
  ): Buffer {
    const arr = JSON.parse(Buffer.from(recvs, options.encodingFormat).toString('utf8')) as EciesEnvelope[];
    const publicKeyString = this.getPublicKeyObjectFromPrivate(receiverPrivateKey).export({ format: 'der', type: 'spki' }).toString(options.encodingFormat);
    const match = arr.find((envelope) => envelope.to_ecdh === publicKeyString);
    if (!match) {
      throw new Error('Recipient envelope not found');
    }
    return this.ecies.decrypt(receiverPrivateKey, match, options);
  }

  private parseKeyBuffer(buffer: Buffer, options: Required<EciesOptions>) {
    const { symmetricKeySize, macKeySize } = options;
    if (buffer.length !== symmetricKeySize + 2 * macKeySize) {
      throw new Error('Invalid key buffer length');
    }
    return {
      symmetricCipherKey: Buffer.from(buffer.subarray(0, symmetricKeySize)),
      ciphertextMacKey: Buffer.from(buffer.subarray(symmetricKeySize, symmetricKeySize + macKeySize)),
      recvsMacKey: Buffer.from(buffer.subarray(symmetricKeySize + macKeySize)),
    };
  }

  private symmetricEncrypt(key: Buffer, data: Buffer, iv: Buffer): Buffer {
    const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);
    return Buffer.concat([cipher.update(data), cipher.final()]);
  }

  private symmetricDecrypt(key: Buffer, data: Buffer, iv: Buffer): Buffer {
    const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
    return Buffer.concat([decipher.update(data), decipher.final()]);
  }

  private computeMac(key: Buffer, data: Buffer, iv: Buffer): Buffer {
    return crypto
      .createHmac('sha256', key)
      .update(Buffer.concat([data, iv]))
      .digest();
  }

  private toPrivateKeyObject(key: crypto.KeyObject | BufferLike | string): crypto.KeyObject {
    if (key instanceof crypto.KeyObject) {
      return key;
    }
    if (typeof key === 'string') {
      return crypto.createPrivateKey(key);
    }
    return crypto.createPrivateKey({ key: toBuffer(key), format: 'der', type: 'sec1' });
  }

  private getPublicKeyObjectFromPrivate(key: crypto.KeyObject | BufferLike | string): crypto.KeyObject {
    if (key instanceof crypto.KeyObject) {
      if (key.type === 'public') {
        return key;
      }
      return crypto.createPublicKey({
        key: key.export({ format: 'pem', type: 'sec1' }),
        format: 'pem',
        type: 'spki',
      });
    }
    if (typeof key === 'string') {
      return crypto.createPublicKey(key);
    }
    return crypto.createPublicKey({ key: toBuffer(key), format: 'der', type: 'spki' });
  }
}
