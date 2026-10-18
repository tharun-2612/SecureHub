const request = require('supertest');

jest.mock('../models/User', () => ({
  findOne: jest.fn(async () => null),
  findById: jest.fn(),
}));

const { createApp } = require('../app');
const { createCorsMiddleware } = require('../config/cors');

describe('CORS origin controls', () => {
  const allowedOrigin = 'http://localhost:5173';
  const otherOrigin = 'https://attacker.example';

  function createCorsTestApp(origins = [allowedOrigin]) {
    return createApp({ allowedOrigins: origins, nodeEnv: 'test' });
  }

  test('returns CORS permission headers for an allowlisted origin', async () => {
    const response = await request(createCorsTestApp())
      .get('/api/health')
      .set('Origin', allowedOrigin)
      .expect(200);

    expect(response.headers['access-control-allow-origin']).toBe(allowedOrigin);
    expect(response.headers.vary).toContain('Origin');
    expect(response.headers['access-control-allow-credentials']).toBeUndefined();
  });

  test('omits CORS permission headers for a disallowed origin', async () => {
    const response = await request(createCorsTestApp())
      .get('/api/health')
      .set('Origin', otherOrigin)
      .expect(200);

    expect(response.headers['access-control-allow-origin']).toBeUndefined();
    expect(response.headers['access-control-allow-credentials']).toBeUndefined();
  });

  test('allows requests without an Origin header to proceed without CORS headers', async () => {
    const response = await request(createCorsTestApp()).get('/api/health').expect(200);

    expect(response.body.status).toBe('ok');
    expect(response.headers['access-control-allow-origin']).toBeUndefined();
  });

  test('handles allowlisted preflight requests for Bearer-token headers', async () => {
    const response = await request(createCorsTestApp())
      .options('/api/users/507f1f77bcf86cd799439011')
      .set('Origin', allowedOrigin)
      .set('Access-Control-Request-Method', 'GET')
      .set('Access-Control-Request-Headers', 'authorization,content-type')
      .expect(204);

    expect(response.headers['access-control-allow-origin']).toBe(allowedOrigin);
    expect(response.headers['access-control-allow-methods']).toContain('GET');
    expect(response.headers['access-control-allow-headers'].toLowerCase()).toContain('authorization');
    expect(response.headers['access-control-allow-headers'].toLowerCase()).toContain('content-type');
    expect(response.headers['access-control-allow-credentials']).toBeUndefined();
  });

  test('does not permit wildcard origins, including in production', () => {
    expect(() => createCorsMiddleware({ allowedOrigins: '*', nodeEnv: 'production' }))
      .toThrow('wildcard origins are not supported');
  });
});
