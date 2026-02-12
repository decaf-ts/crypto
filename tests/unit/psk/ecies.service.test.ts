import { KeyGeneratorService } from '../../../src/psk/services/key-generator.service';
import { PskEciesService } from '../../../src/psk/services/ecies.service';

describe('PskEciesService', () => {
  const keyGen = new KeyGeneratorService();
  const ecies = new PskEciesService();
  const { privateKey, publicKey } = keyGen.generateKeyPair();

  it('encrypts and decrypts payloads consistently', () => {
    const message = 'hello world';
    const envelope = ecies.encrypt(publicKey, message);
    const decrypted = ecies.decrypt(privateKey, envelope);
    expect(decrypted.toString()).toBe(message);
  });

  it('exposes envelope fields encoded as base64', () => {
    const message = Buffer.from([1, 2, 3]);
    const envelope = ecies.encrypt(publicKey, message);
    expect(envelope).toHaveProperty('ct');
    expect(envelope).toHaveProperty('iv');
    expect(envelope.ct).toMatch(/[A-Za-z0-9+/=]+/);
  });
});
