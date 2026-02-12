import crypto from 'crypto';
import { PskJoseService } from '../../../src/psk/services/jose.service';

describe('PskJoseService', () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const service = new PskJoseService();

  it('signs and verifies payloads using CompactSign', async () => {
    const message = 'compact-jose';
    const result = await service.compactSign(message, privateKey, { alg: 'ES256' });
    const verified = await service.compactVerify(result.token, publicKey);
    expect(verified.plaintext.toString()).toBe(message);
    expect(verified.header).toHaveProperty('alg', 'ES256');
  });
  it('encrypts and decrypts payloads via CompactEncrypt', async () => {
    const message = 'encrypt-me';
    const encrypted = await service.compactEncrypt(message, publicKey, { alg: 'ECDH-ES', enc: 'A256GCM' });
    const decrypted = await service.compactDecrypt(encrypted, privateKey);
    expect(decrypted.plaintext.toString()).toBe(message);
    expect(decrypted.header).toHaveProperty('enc', 'A256GCM');
  });
});
