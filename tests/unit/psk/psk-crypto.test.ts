import { default as pskCrypto } from '../../../src/psk';

describe('psk-crypto compatibility layer', () => {
  it('signs and verifies payloads same as legacy', () => {
    const { privateKey, publicKey } = pskCrypto.generateKeyPair();
    const formatted = pskCrypto.convertKeys(privateKey, publicKey);

    const payload = 'it works';
    const signature = pskCrypto.sign('sha256', payload, formatted.privateKey);
    const verified = pskCrypto.verify('sha256', payload, formatted.publicKey, signature);

    expect(verified).toBe(true);
    expect(signature).toBeInstanceOf(Buffer);
  });

  it('generates uids honoring length parameter', () => {
    const lengths = [16, 32, 64, 128];
    lengths.forEach((size) => {
      const uid = pskCrypto.generateUid(size);
      expect(uid).toHaveLength(size);
    });
  });

  it('produces consistent hash values for objects', () => {
    const obj = { foo: 'bar', nested: { value: 2 } };
    const h1 = pskCrypto.hash('sha256', JSON.stringify(obj));
    const h2 = pskCrypto.hash('sha256', JSON.stringify(obj));
    expect(Buffer.isBuffer(h1)).toBe(true);
    expect(Buffer.compare(h1 as Buffer, h2 as Buffer)).toBe(0);
  });

  it('round trips base58 operations', () => {
    const payload = Buffer.from('round-trip');
    const encoded = pskCrypto.pskBase58Encode(payload);
    expect(typeof encoded).toBe('string');
    const decoded = pskCrypto.pskBase58Decode(encoded);
    expect(decoded.equals(payload)).toBe(true);
  });

  it('produces safe uid variants when salt provided', () => {
    const safe = pskCrypto.generateSafeUid('pass', 'extra');
    expect(typeof safe).toBe('string');
    expect(safe.length).toBeGreaterThan(0);
  });
});
