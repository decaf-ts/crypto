import { PskJwtService } from '../../../src/psk/services/jwt.service';

describe('PskJwtService', () => {
  const service = new PskJwtService();
  const payload = { hello: 'world' };
  const secret = 'psk-secret';
  let token: string;

  it('signs payloads asynchronously', async () => {
    token = await service.sign(payload, secret, { expiresIn: '1h' });
    expect(typeof token).toBe('string');
  });

  it('verifies tokens and returns the payload', async () => {
    const decoded = await service.verify(token, secret);
    expect((decoded as Record<string, unknown>).hello).toBe('world');
  });

  it('decodes without verifying', () => {
    const decoded = service.decode(token);
    expect((decoded as Record<string, unknown>).hello).toBe('world');
  });
});
