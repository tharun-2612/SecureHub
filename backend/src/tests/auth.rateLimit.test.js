const bcrypt = require('bcrypt');
const request = require('supertest');

jest.mock('../models/User', () => ({
  create: jest.fn(),
  findOne: jest.fn(),
}));

const { createApp } = require('../app');
const User = require('../models/User');

describe('authentication rate limits', () => {
  const email = 'rate.limit@example.com';
  const password = 'StrongPass1!';
  const passwordHash = '$2b$12$test-password-hash';
  const jwtSecret = 'test-rate-limit-jwt-secret';

  function createTestApp() {
    return createApp({
      rateLimits: {
        login: { windowMs: 60_000, limit: 2 },
        register: { windowMs: 60_000, limit: 2 },
      },
    });
  }

  beforeEach(() => {
    process.env.JWT_SECRET = jwtSecret;
    User.findOne.mockResolvedValue({
      _id: { toString: () => '507f1f77bcf86cd799439011' },
      email,
      role: 'user',
      passwordHash,
    });
    User.create.mockImplementation(async (data) => ({
      _id: { toString: () => '507f1f77bcf86cd799439011' },
      role: 'user',
      createdAt: new Date('2026-01-01T00:00:00.000Z'),
      updatedAt: new Date('2026-01-01T00:00:00.000Z'),
      ...data,
    }));
    jest.spyOn(bcrypt, 'compare').mockResolvedValue(true);
    jest.spyOn(bcrypt, 'hash').mockResolvedValue(passwordHash);
  });

  afterEach(() => {
    jest.restoreAllMocks();
    jest.clearAllMocks();
  });

  test('allows requests below the configured limits', async () => {
    const app = createTestApp();

    for (let attempt = 0; attempt < 2; attempt += 1) {
      await request(app).post('/api/auth/login').send({ email, password }).expect(200);
      await request(app)
        .post('/api/auth/register')
        .send({ email: `user${attempt}@example.com`, password })
        .expect(201);
    }
  });

  test('limits login attempts before password comparison and returns a generic 429', async () => {
    const app = createTestApp();

    await request(app).post('/api/auth/login').send({ email, password }).expect(200);
    await request(app).post('/api/auth/login').send({ email, password }).expect(200);
    const response = await request(app)
      .post('/api/auth/login')
      .send({ email, password })
      .expect(429);

    expect(bcrypt.compare).toHaveBeenCalledTimes(2);
    expect(response.body).toEqual({
      message: 'Too many requests. Please try again later.',
    });
    expect(JSON.stringify(response.body)).not.toContain(email);
    expect(JSON.stringify(response.body)).not.toContain(password);
    expect(JSON.stringify(response.body)).not.toContain(passwordHash);
    expect(JSON.stringify(response.body)).not.toContain(jwtSecret);
  });

  test('limits registration attempts before password hashing and returns a generic 429', async () => {
    const app = createTestApp();

    await request(app)
      .post('/api/auth/register')
      .send({ email: 'first@example.com', password })
      .expect(201);
    await request(app)
      .post('/api/auth/register')
      .send({ email: 'second@example.com', password })
      .expect(201);
    const response = await request(app)
      .post('/api/auth/register')
      .send({ email, password })
      .expect(429);

    expect(bcrypt.hash).toHaveBeenCalledTimes(2);
    expect(response.body).toEqual({
      message: 'Too many requests. Please try again later.',
    });
    expect(JSON.stringify(response.body)).not.toContain(email);
    expect(JSON.stringify(response.body)).not.toContain(password);
    expect(JSON.stringify(response.body)).not.toContain(passwordHash);
    expect(JSON.stringify(response.body)).not.toContain(jwtSecret);
  });
});
