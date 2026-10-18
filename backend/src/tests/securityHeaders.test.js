const jwt = require('jsonwebtoken');
const request = require('supertest');

jest.mock('../models/User', () => ({
  findOne: jest.fn(async () => null),
  findById: jest.fn(async (userId) => ({
    _id: { toString: () => userId },
    email: 'profile@example.com',
    role: 'user',
    createdAt: new Date('2026-01-01T00:00:00.000Z'),
    updatedAt: new Date('2026-01-01T00:00:00.000Z'),
  })),
}));

const { createApp } = require('../app');

describe('HTTP security headers', () => {
  const jwtSecret = 'test-security-headers-secret';
  const userId = '507f1f77bcf86cd799439011';

  function expectSecurityHeaders(response) {
    expect(response.headers['x-content-type-options']).toBe('nosniff');
    expect(response.headers['x-frame-options']).toBe('DENY');
    expect(response.headers['x-powered-by']).toBeUndefined();
    expect(response.headers['content-security-policy']).toBeUndefined();
  }

  beforeAll(() => {
    process.env.JWT_SECRET = jwtSecret;
  });

  test('adds security headers to health, authentication, and profile responses', async () => {
    const app = createApp();
    const healthResponse = await request(app).get('/api/health').expect(200);
    expect(healthResponse.body.status).toBe('ok');
    expectSecurityHeaders(healthResponse);

    const authResponse = await request(app)
      .post('/api/auth/login')
      .send({ email: 'missing@example.com', password: 'StrongPass1!' })
      .expect(401);
    expect(authResponse.body.message).toBe('Invalid email or password');
    expectSecurityHeaders(authResponse);

    const token = jwt.sign({ sub: userId, role: 'user' }, jwtSecret, { expiresIn: '1h' });
    const profileResponse = await request(app)
      .get(`/api/users/${userId}`)
      .set('Authorization', `Bearer ${token}`)
      .expect(200);
    expect(profileResponse.body.user.email).toBe('profile@example.com');
    expectSecurityHeaders(profileResponse);
  });

  test('adds security headers to API 404 and error responses', async () => {
    const app = createApp();
    const notFoundResponse = await request(app).get('/api/not-a-route').expect(404);
    expectSecurityHeaders(notFoundResponse);

    const errorResponse = await request(app)
      .post('/api/auth/register')
      .send({ email: 'invalid@example.com' })
      .expect(400);
    expectSecurityHeaders(errorResponse);
  });

  test.each(['/robots.txt', '/sitemap.xml'])(
    'adds a complete no-content CSP to the Express-style 404 for %s',
    async (path) => {
      const response = await request(createApp()).get(path).expect(404);
      const policy = response.headers['content-security-policy'];

      expect(response.headers['content-type']).toContain('text/html');
      expect(policy).toContain("default-src 'none'");
      expect(policy).toContain("frame-ancestors 'none'");
      expect(policy).toContain("form-action 'none'");
      expect(response.headers['x-frame-options']).toBe('DENY');
      expect(response.headers['x-content-type-options']).toBe('nosniff');
      expect(response.text).toContain(`Cannot GET ${path}`);
    }
  );

  test('keeps HSTS disabled outside production', async () => {
    const originalNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'development';

    try {
      const response = await request(createApp()).get('/api/health').expect(200);
      expect(response.headers['strict-transport-security']).toBeUndefined();
    } finally {
      if (originalNodeEnv === undefined) {
        delete process.env.NODE_ENV;
      } else {
        process.env.NODE_ENV = originalNodeEnv;
      }
    }
  });

  test('enables HSTS only for production with a six-month policy', async () => {
    const originalNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';

    try {
      const response = await request(createApp()).get('/api/health').expect(200);
      expect(response.headers['strict-transport-security']).toBe('max-age=15552000');
    } finally {
      if (originalNodeEnv === undefined) {
        delete process.env.NODE_ENV;
      } else {
        process.env.NODE_ENV = originalNodeEnv;
      }
    }
  });
});
