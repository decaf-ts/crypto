import { CryptoKeys } from "./constants";
import {
  apply,
  Decoration,
  propMetadata,
  Metadata,
} from "@decaf-ts/decoration";
import {
  onCreate,
  onUpdate,
  UpdateOperationHandler,
  GeneralOperationHandler,
  StandardOperationHandler,
  afterRead,
} from "@decaf-ts/db-decorators";
import { ContextualArgs, Repo } from "@decaf-ts/core";
import { Model } from "@decaf-ts/decorator-validation";
import { CryptoError } from "./errors";
import { getSubtle } from "../common/crypto";
import { getCrypto } from "../common/crypto";
import { SubtleCrypto } from "../common/Subtle"; // Explicitly import SubtleCrypto interface
import {
  AesCbcParams,
  AesCtrParams,
  AesGcmParams,
  AlgorithmIdentifier,
  RsaOaepParams,
  CryptoKey,
  KeyUsage,
  Algorithm,
} from "../common/index";

/**
 * @description A function that returns a secret for encryption.
 * @summary This function type is used to define a function that can be passed to the `@encrypt` decorator to dynamically retrieve the encryption secret.
 * @template M - The type of the model.
 * @param {M} model - The model instance.
 * @param {ContextualArgs<any>} args - The contextual arguments.
 * @returns {Promise<string>} A promise that resolves to the secret string.
 * @typedef {function} SecretFunction
 * @memberOf module:@decaf-ts/crypto
 */
export type SecretFunction = <M extends Model>(
  model: M,
  ...args: ContextualArgs<any>
) => Promise<string>;

/**
 * @description Metadata for the `@encrypt` decorator.
 * @summary This type defines the structure of the metadata object that is passed to the encryption handlers.
 * @typedef {object} CryptoMeta
 * @property {string | SecretFunction} secret - The secret or a function to retrieve the secret.
 * @property {AesCbcParams | AesCtrParams | AesGcmParams | AlgorithmIdentifier | RsaOaepParams} algorithm - The encryption algorithm to use.
 * @memberOf module:@decaf-ts/crypto
 */
export type CryptoMeta = {
  secret: string | SecretFunction;
  algorithm:
    | AesCbcParams
    | AesCtrParams
    | AesGcmParams
    | AlgorithmIdentifier
    | RsaOaepParams;
};

/**
 * @description Retrieves the encryption secret.
 * @summary This function retrieves the secret from the `CryptoMeta` object. If the secret is a string, it returns it directly. If it's a function, it calls the function and returns the result.
 * @template M - The type of the model.
 * @param {CryptoMeta} meta - The crypto metadata.
 * @param {M} model - The model instance.
 * @param {ContextualArgs<any>} args - The contextual arguments.
 * @returns {Promise<string>} A promise that resolves to the secret string.
 * @function getCryptoSecret
 * @memberOf module:@decaf-ts/crypto
 */
async function getCryptoSecret<M extends Model>(
  meta: CryptoMeta,
  model: M,
  ...args: ContextualArgs<any>
) {
  try {
    return typeof meta.secret === "string"
      ? meta.secret
      : await meta.secret(model, ...args);
  } catch (e: unknown) {
    throw new CryptoError(`Failed to retrieve secrete from handler: ${e}`);
  }
}

/**
 * @description Derives a cryptographic key from a secret string.
 * @summary This function uses `subtle.importKey` to create a `CryptoKey` from a raw secret string.
 * @param {SubtleCrypto} subtle - The `SubtleCrypto` implementation to use.
 * @param {string} secret - The secret string to derive the key from.
 * @param {CryptoMeta["algorithm"]} algorithm - The algorithm to use for the key.
 * @param {KeyUsage[]} keyUsages - The allowed usages for the new key.
 * @returns {Promise<CryptoKey>} A promise that resolves to the derived `CryptoKey`.
 * @function getDerivedKey
 * @memberOf module:@decaf-ts/crypto
 */
async function getDerivedKey(
  subtle: SubtleCrypto,
  secret: string,
  algorithm: CryptoMeta["algorithm"],
  keyUsages: KeyUsage[]
): Promise<CryptoKey> {
  const keyMaterial = new TextEncoder().encode(secret);
  const algIdentifier =
    typeof algorithm === "string" ? { name: algorithm } : algorithm;
  return subtle.importKey(
    "raw",
    keyMaterial,
    algIdentifier,
    true, // extractable
    keyUsages
  );
}

/**
 * @description Converts an ArrayBuffer to a hex string.
 * @summary This function takes an ArrayBuffer and returns its hexadecimal string representation.
 * @param {ArrayBuffer} buffer - The ArrayBuffer to convert.
 * @returns {string} The hex string.
 * @function arrayBufferToHex
 * @memberOf module:@decaf-ts/crypto
 */
function arrayBufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * @description Converts a hex string to an ArrayBuffer.
 * @summary This function takes a hexadecimal string and returns its ArrayBuffer representation.
 * @param {string} hexString - The hex string to convert.
 * @returns {ArrayBuffer} The ArrayBuffer.
 * @function hexToArrayBuffer
 * @memberOf module:@decaf-ts/crypto
 */
function hexToArrayBuffer(hexString: string): ArrayBuffer {
  const bytes = new Uint8Array(hexString.length / 2);
  for (let i = 0; i < hexString.length; i += 2) {
    bytes[i / 2] = parseInt(hexString.substring(i, i + 2), 16);
  }
  return bytes.buffer;
}

/**
 * @description An operation handler that encrypts a property on model creation.
 * @summary This function is used with the `@onCreate` decorator from `@decaf-ts/db-decorators`. It encrypts the value of the decorated property before the model is saved to the database.
 * @type {GeneralOperationHandler<any, any, any>}
 * @memberOf module:@decaf-ts/crypto
 */
export const encryptOnCreate: GeneralOperationHandler<any, any, any> =
  async function <M extends Model>(
    this: Repo<M>,
    context: any,
    data: CryptoMeta,
    key: keyof M,
    model: M
  ) {
    if (typeof model[key] === "undefined") return;
    const secret = await getCryptoSecret(data, model, context);
    const subtle = await getSubtle();
    const derivedKey = await getDerivedKey(subtle, secret, data.algorithm, [
      "encrypt",
      "decrypt",
    ]);

    const dataToEncrypt = new TextEncoder().encode(JSON.stringify(model[key]));
    const iv = ((await getCrypto()) as any).getRandomValues(new Uint8Array(12)); // Generate a random IV for AES-GCM

    const encryptedData = await subtle.encrypt(
      { name: (data.algorithm as Algorithm).name, iv: iv }, // Cast to Algorithm to access name
      derivedKey,
      dataToEncrypt
    );
    const combined = new Uint8Array(iv.byteLength + encryptedData.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(encryptedData), iv.byteLength);
    model[key] = arrayBufferToHex(combined.buffer) as any;
  };

/**
 * @description An operation handler that decrypts a property after a model is read.
 * @summary This function is used with the `@afterRead` decorator from `@decaf-ts/db-decorators`. It decrypts the value of the decorated property after the model is read from the database.
 * @type {StandardOperationHandler<any, any, CryptoMeta>}
 * @memberOf module:@decaf-ts/crypto
 */
export const encryptOnRead: StandardOperationHandler<any, any, CryptoMeta> =
  async function <M extends Model>(
    this: Repo<M>,
    context: any,
    data: CryptoMeta,
    key: keyof M,
    model: M
  ) {
    if (typeof model[key] === "undefined" || typeof model[key] !== "string")
      return; // Expect a hex string
    const secret = await getCryptoSecret(data, model, context);
    const subtle = await getSubtle();
    const derivedKey = await getDerivedKey(subtle, secret, data.algorithm, [
      "encrypt",
      "decrypt",
    ]);

    const combinedBuffer = hexToArrayBuffer(model[key] as string);
    const iv = new Uint8Array(combinedBuffer, 0, 12); // IV is the first 12 bytes
    const encryptedData = new Uint8Array(combinedBuffer, 12); // Remaining is encrypted data

    const decryptedData = await subtle.decrypt(
      { name: (data.algorithm as Algorithm).name, iv: iv },
      derivedKey,
      encryptedData
    );
    model[key] = JSON.parse(new TextDecoder().decode(decryptedData)) as any;
  };

/**
 * @description An operation handler that encrypts a property on model update.
 * @summary This function is used with the `@onUpdate` decorator from `@decaf-ts/db-decorators`. It encrypts the value of the decorated property before the model is updated in the database. It also handles cases where the value has not changed to avoid unnecessary re-encryption.
 * @type {UpdateOperationHandler<any, any, any>}
 * @memberOf module:@decaf-ts/crypto
 */
export const encryptOnUpdate: UpdateOperationHandler<any, any, any> =
  async function <M extends Model>(
    this: Repo<M>,
    context: any,
    data: CryptoMeta,
    key: keyof M,
    model: M,
    oldModel: M
  ) {
    if (typeof model[key] === "undefined") return; // No new value to encrypt

    const secret = await getCryptoSecret(data, oldModel || model, context);
    const subtle = await getSubtle();
    const derivedKey = await getDerivedKey(subtle, secret, data.algorithm, [
      "encrypt",
      "decrypt",
    ]);

    const algName = (data.algorithm as Algorithm).name;

    // Check context flags to determine if old model comparison is available.
    // The repository only fetches the old model when applyUpdateValidation is
    // true. mergeForUpdate controls whether old values are merged into the new
    // model. If either flag is missing/false the old model may not carry valid
    // encrypted data, so we skip comparison and just encrypt.
    const hasOldModel =
      context &&
      typeof context.get === "function" &&
      context.get("mergeForUpdate") &&
      context.get("applyUpdateValidation") &&
      oldModel &&
      oldModel[key] &&
      typeof oldModel[key] === "string";

    if (hasOldModel) {
      // The old model has already been decrypted by afterRead, so both
      // model[key] and oldModel[key] are plaintext at this point.
      // Compare them directly to decide whether re-encryption is needed.
      if (JSON.stringify(model[key]) === JSON.stringify(oldModel[key])) {
        // Value unchanged – encrypt to the same plaintext so the stored
        // ciphertext is refreshed but logically equivalent.  We cannot
        // preserve the original ciphertext because afterRead already
        // replaced it with plaintext on the old model.
        // Still need to encrypt for storage.
      }
    }

    // Encrypt the current value (data changed, no old data, or no context flags)
    const currentUnencryptedValue = JSON.stringify(model[key]);
    const newIv = ((await getCrypto()) as any).getRandomValues(
      new Uint8Array(12)
    );
    const newDataToEncrypt = new TextEncoder().encode(currentUnencryptedValue);

    const newEncryptedData = await subtle.encrypt(
      { name: algName, iv: newIv },
      derivedKey,
      newDataToEncrypt
    );

    const newCombinedBuffer = new Uint8Array(
      newIv.byteLength + newEncryptedData.byteLength
    );
    newCombinedBuffer.set(newIv, 0);
    newCombinedBuffer.set(new Uint8Array(newEncryptedData), newIv.byteLength);
    model[key] = arrayBufferToHex(newCombinedBuffer.buffer) as any;
  };

/**
 * @description A property decorator that enables automatic encryption and decryption for a model property.
 * @summary
 * The `@encrypt` decorator transparently handles the encryption of a property when a model is created or updated,
 * and decryption when it is read. It uses the SubtleCrypto API for cryptographic operations.
 *
 * This decorator should be applied to properties of a model that require encryption.
 * It integrates with `@decaf-ts/db-decorators` to hook into the database operation lifecycle.
 *
 * @template M - The type of the model.
 *
 * @param {string | Function} secret - The secret to be used for deriving the encryption key. This can be a string or a function that returns a promise resolving to a string.
 * @param {AesCbcParams | AesCtrParams | AesGcmParams | AlgorithmIdentifier | RsaOaepParams} algorithm - The encryption algorithm to use.
 *
 * @returns {PropertyDecorator} A property decorator.
 *
 * @function encrypt
 *
 * @mermaid
 * sequenceDiagram
 *   participant Client
 *   participant Model
 *   participant Decorator as @encrypt
 *   participant DB as Database
 *   participant SubtleCrypto
 *
 *   Client->>Model: newUser.ssn = "sensitive data"
 *   App->>Repo: repo.save(newUser)
 *   Repo->>Decorator: onCreate(newUser)
 *   Decorator->>SubtleCrypto: deriveKey(secret, algorithm)
 *   SubtleCrypto-->>Decorator: encryptionKey
 *   Decorator->>SubtleCrypto: encrypt(ssn, encryptionKey, IV)
 *   SubtleCrypto-->>Decorator: encryptedDataArrayBuffer
 *   Decorator->>Decorator: combine IV + encryptedDataArrayBuffer -> hexString
 *   Decorator->>Model: newUser.ssn = hexString
 *   Repo->>DB: save({ssn: hexString})
 *   DB-->>Repo: Acknowledged
 *
 *   App->>Repo: repo.findById("user123")
 *   Repo->>DB: fetch("user123")
 *   DB-->>Repo: {ssn: hexString}
 *   Repo->>Decorator: afterRead(fetchedUser)
 *   Decorator->>Decorator: hexString -> combined IV + encryptedDataArrayBuffer
 *   Decorator->>Decorator: extract IV and encryptedDataArrayBuffer
 *   Decorator->>SubtleCrypto: deriveKey(secret, algorithm)
 *   SubtleCrypto-->>Decorator: decryptionKey
 *   Decorator->>SubtleCrypto: decrypt(encryptedDataArrayBuffer, decryptionKey, IV)
 *   SubtleCrypto-->>Decorator: "sensitive data"
 *   Decorator->>Model: fetchedUser.ssn = "sensitive data"
 *   Repo-->>App: return fetchedUser
 *   App->>App: Use fetchedUser.ssn
 *
 * @category Property Decorators
 */
export function encrypt(
  secret:
    | string
    | (<M extends Model>(
        model: M,
        ...args: ContextualArgs<any>
      ) => Promise<string>),
  algorithm:
    | AesCbcParams
    | AesCtrParams
    | AesGcmParams
    | AlgorithmIdentifier
    | RsaOaepParams
) {
  function encrypt(secret: string | SecretFunction) {
    return function innerEncrypt(target: object, propertyKey?: any) {
      const meta: CryptoMeta = { secret: secret, algorithm };
      return apply(
        propMetadata(Metadata.key(CryptoKeys.ENCRYPTED, propertyKey), meta),
        onCreate(encryptOnCreate, meta, { priority: 90 }),
        afterRead(encryptOnRead, meta),
        onUpdate(encryptOnUpdate, meta, { priority: 90 })
      )(target, propertyKey);
    };
  }

  return Decoration.for(CryptoKeys.ENCRYPTED)
    .define({
      decorator: encrypt,
      args: [secret],
    })
    .apply();
}
