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

export type SecretFunction = <M extends Model>(
  model: M,
  ...args: ContextualArgs<any>
) => Promise<string>;

export type CryptoMeta = {
  secret: string | SecretFunction;
  algorithm:
    | AesCbcParams
    | AesCtrParams
    | AesGcmParams
    | AlgorithmIdentifier
    | RsaOaepParams;
};

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

async function getDerivedKey(
  subtle: SubtleCrypto,
  secret: string,
  algorithm: AlgorithmIdentifier, // Changed type to AesKeyAlgorithm
  keyUsages: KeyUsage[]
): Promise<CryptoKey> {
  const keyMaterial = new TextEncoder().encode(secret);
  return subtle.importKey(
    "raw",
    keyMaterial,
    { name: algorithm as string }, // Pass only the name property for algorithm identifier
    true, // extractable
    keyUsages
  );
}

function arrayBufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToArrayBuffer(hexString: string): ArrayBuffer {
  const bytes = new Uint8Array(hexString.length / 2);
  for (let i = 0; i < hexString.length; i += 2) {
    bytes[i / 2] = parseInt(hexString.substring(i, i + 2), 16);
  }
  return bytes.buffer;
}

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
    const derivedKey = await getDerivedKey(
      subtle,
      secret,
      data.algorithm as AlgorithmIdentifier,
      ["encrypt", "decrypt"]
    ); // Get the key

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

    const secret = await getCryptoSecret(data, oldModel, context); // Use oldModel to get secret if dynamic
    const subtle = await getSubtle();
    const derivedKey = await getDerivedKey(subtle, secret, data.algorithm, [
      "encrypt",
      "decrypt",
    ]);

    // 1. Get current (unencrypted) value
    const currentUnencryptedValue = JSON.stringify(model[key]);

    // 2. Try to decrypt old value for comparison
    let oldUnencryptedValue: string | undefined;
    if (oldModel && oldModel[key] && typeof oldModel[key] === "string") {
      try {
        const oldCombinedBuffer = hexToArrayBuffer(oldModel[key] as string);
        const oldIv = new Uint8Array(oldCombinedBuffer, 0, 12);
        const oldEncryptedData = new Uint8Array(oldCombinedBuffer, 12);

        const oldDecryptedData = await subtle.decrypt(
          { name: (data.algorithm as Algorithm).name, iv: oldIv },
          derivedKey,
          oldEncryptedData
        );
        oldUnencryptedValue = new TextDecoder().decode(oldDecryptedData);
      } catch (e: unknown) {
        // Log or handle decryption errors if old data is malformed
        console.warn(`Failed to decrypt old value for comparison: ${e}`);
      }
    }

    // 3. Compare current unencrypted value with old unencrypted value
    if (
      oldUnencryptedValue !== undefined &&
      currentUnencryptedValue === oldUnencryptedValue
    ) {
      // Data hasn't changed, no need to re-encrypt or update
      // To avoid unnecessary DB writes, keep the old encrypted value if it exists
      if (oldModel && oldModel[key] && typeof oldModel[key] === "string") {
        model[key] = oldModel[key];
      }
      return;
    }

    // 4. If data changed or no old data, proceed with new encryption
    const newIv = ((await getCrypto()) as any).getRandomValues(
      new Uint8Array(12)
    );
    const newDataToEncrypt = new TextEncoder().encode(currentUnencryptedValue);

    const newEncryptedData = await subtle.encrypt(
      { name: (data.algorithm as Algorithm).name, iv: newIv },
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
