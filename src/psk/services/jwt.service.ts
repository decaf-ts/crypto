import jwt, { DecodeOptions, JwtPayload, SignCallback, SignOptions, VerifyCallback, VerifyOptions } from 'jsonwebtoken';

/**
 * @description A service for JWT (JSON Web Token) operations.
 * @summary This service provides methods for signing, verifying, and decoding JWTs using the `jsonwebtoken` library.
 * @class PskJwtService
 * @memberOf module:@decaf-ts/crypto/psk
 */
export class PskJwtService {
  /**
   * @description Signs a JWT payload.
   * @summary This method signs a payload and returns a JWT token.
   * @param {string | object | Buffer} payload - The payload to sign.
   * @param {jwt.Secret} secretOrPrivateKey - The secret or private key for signing.
   * @param {SignOptions} [options] - Options for signing.
   * @returns {Promise<string>} A promise that resolves to the JWT token.
   * @function sign
   * @memberOf module:@decaf-ts/crypto/psk
   */
  async sign(
    payload: string | object | Buffer,
    secretOrPrivateKey: jwt.Secret,
    options?: SignOptions
  ): Promise<string> {
    return new Promise((resolve, reject) => {
      const callback: SignCallback = (err, token) => {
        if (err) {
          return reject(err);
        }
        if (!token) {
          return reject(new Error('Token generation failed'));
        }
        resolve(token);
      };

      jwt.sign(payload, secretOrPrivateKey, options ?? {}, callback);
    });
  }

  /**
   * @description Verifies a JWT.
   * @summary This method verifies a JWT and returns its payload.
   * @param {string} token - The JWT to verify.
   * @param {jwt.Secret} secretOrPublicKey - The secret or public key for verification.
   * @param {VerifyOptions} [options] - Options for verification.
   * @returns {Promise<string | JwtPayload>} A promise that resolves to the decoded payload.
   * @function verify
   * @memberOf module:@decaf-ts/crypto/psk
   */
  async verify(
    token: string,
    secretOrPublicKey: jwt.Secret,
    options?: VerifyOptions
  ): Promise<string | JwtPayload> {
    return new Promise((resolve, reject) => {
      const callback: VerifyCallback<string | JwtPayload> = (err, decoded) => {
        if (err) {
          return reject(err);
        }
        resolve(decoded as string | JwtPayload);
      };

      jwt.verify(token, secretOrPublicKey, options ?? {}, callback);
    });
  }

  /**
   * @description Decodes a JWT without verification.
   * @summary This method decodes a JWT and returns its payload without verifying the signature.
   * @param {string} token - The JWT to decode.
   * @param {DecodeOptions} [options] - Options for decoding.
   * @returns {string | JwtPayload | null} The decoded payload.
   * @function decode
   * @memberOf module:@decaf-ts/crypto/psk
   */
  decode(token: string, options?: DecodeOptions): string | JwtPayload | null {
    return jwt.decode(token, options);
  }
}
