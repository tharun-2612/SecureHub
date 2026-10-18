const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const request = require('supertest');

const users = [];

jest.mock('../models/User', () => ({
  findOne: jest.fn(async (query) => users.find((user) => user.email === query.email) || null),
  deleteMany: jest.fn(async () => {
    users.length = 0;
  }),
}));

const { createApp } = require('../app');
const User = require('../models/User');
const app = createApp({
  rateLimits: {
    login: { windowMs: 60_000, limit: 10_000 },
    register: { windowMs: 60_000, limit: 10_000 },
  },
});

describe('POST /api/auth/login', () => {
  const jwtSecret = 'test-login-jwt-secret';
  const validPassword = 'StrongPass1!';

  beforeAll(() => {
    process.env.JWT_SECRET = jwtSecret;
    process.env.JWT_EXPIRES_IN = '1h';
  });

  beforeEach(async () => {
    users.push({
      _id: 'user-1',
      email: 'login.user@example.com',
      role: 'user',
      passwordHash: await bcrypt.hash(validPassword, 12),
    });
  });

  afterEach(async () => {
    await User.deleteMany({});
    jest.clearAllMocks();
  });

  test('successfully logs in a user', async () => {
    const response = await request(app)
      .post('/api/auth/login')
      .send({
        email: ' Login.User@Example.COM ',
        password: validPassword,
      })
      .expect(200);

    expect(response.body.user).toEqual({
      id: 'user-1',
      email: 'login.user@example.com',
      role: 'user',
    });
    expect(response.body.token).toBeDefined();
  });

  test('rejects an incorrect password with a generic error', async () => {
    const response = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'login.user@example.com',
        password: 'WrongPass1!',
      })
      .expect(401);

    expect(response.body.message).toBe('Invalid email or password');
  });

  test('rejects an unknown email with the same generic error', async () => {
    const response = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'unknown@example.com',
        password: validPassword,
      })
      .expect(401);

    expect(response.body.message).toBe('Invalid email or password');
  });

  test('rejects missing credentials', async () => {
    const response = await request(app)
      .post('/api/auth/login')
      .send({ email: 'login.user@example.com' })
      .expect(400);

    expect(response.body.message).toBe('Email and password are required');
  });

  test.each([
    ['object', { $ne: null }],
    ['array', ['login.user@example.com']],
  ])('rejects an email supplied as an %s', async (kind, email) => {
    await request(app)
      .post('/api/auth/login')
      .send({ email, password: validPassword })
      .expect(400);
    expect(User.findOne).not.toHaveBeenCalled();
  });

  test.each([
    ['object', { $ne: null }],
    ['array', [validPassword]],
  ])('rejects a password supplied as an %s', async (kind, password) => {
    await request(app)
      .post('/api/auth/login')
      .send({ email: 'login.user@example.com', password })
      .expect(400);
    expect(User.findOne).not.toHaveBeenCalled();
  });

  test('rejects MongoDB operator injection and oversized credentials', async () => {
    await request(app)
      .post('/api/auth/login')
      .send({ email: { $ne: null }, password: validPassword })
      .expect(400);
    expect(User.findOne).not.toHaveBeenCalled();

    await request(app)
      .post('/api/auth/login')
      .send({ email: 'login.user@example.com', password: `${'A1!a'.repeat(33)}` })
      .expect(400);
    expect(User.findOne).not.toHaveBeenCalled();
  });

  test('generates a valid signed JWT after successful login', async () => {
    const response = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'login.user@example.com',
        password: validPassword,
      })
      .expect(200);

    const decoded = jwt.verify(response.body.token, jwtSecret);

    expect(decoded.sub).toBe('user-1');
    expect(decoded.role).toBe('user');
    expect(decoded.exp).toBeGreaterThan(decoded.iat);
  });

  test('JWT payload contains only intended claims', async () => {
    const response = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'login.user@example.com',
        password: validPassword,
      })
      .expect(200);

    const decoded = jwt.verify(response.body.token, jwtSecret);

    expect(Object.keys(decoded).sort()).toEqual(['exp', 'iat', 'role', 'sub']);
  });

  test('password and passwordHash are not present in the JWT', async () => {
    const response = await request(app)
      .post('/api/auth/login')
      .send({
        email: 'login.user@example.com',
        password: validPassword,
      })
      .expect(200);

    const decoded = jwt.verify(response.body.token, jwtSecret);

    expect(decoded.password).toBeUndefined();
    expect(decoded.passwordHash).toBeUndefined();
  });
});
