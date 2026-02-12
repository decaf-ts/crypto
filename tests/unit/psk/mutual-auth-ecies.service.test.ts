import crypto from 'crypto';
import { PskMutualAuthEciesService, EciesSigningKeyPair } from '../../../src/psk/services/ecies-mutual-auth.service';

describe('PskMutualAuthEciesService', () => {
  const service = new PskMutualAuthEciesService();
  const receiverA = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
  const receiverB = crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
  const sender: EciesSigningKeyPair = {
    privateKey: crypto.createPrivateKey(receiverA.privateKey.export({ format: 'pem', type: 'sec1' })),
    publicKey: crypto.createPublicKey(receiverA.publicKey.export({ format: 'pem', type: 'spki' })),
  };

  it('encrypts and decrypts digital-signature envelopes', () => {
    const envelope = service.encrypt_ds(sender, receiverB.publicKey, 'secret');
    const decoded = service.decrypt_ds(receiverB.privateKey, envelope);
    expect(decoded.message.toString()).toBe('secret');
  });

  it('group encrypt/decrypt produces consistent payload', () => {
    const envelope = service.encrypt_group('batch', [receiverA.publicKey, receiverB.publicKey]);
    const output = service.decrypt_group(receiverB.privateKey, envelope);
    expect(output.toString()).toBe('batch');
  });

  it('group ds encryption keeps sender signature intact', () => {
    const envelope = service.encrypt_group_ds(sender, [receiverA.publicKey, receiverB.publicKey], 'group');
    const decoded = service.decrypt_group_ds(receiverA.privateKey, envelope);
    expect(decoded.message.toString()).toBe('group');
  });
});
