const bcrypt = require('bcrypt');
const request = require('supertest');

const users = [];

jest.mock('../models/User', () => ({
  create: jest.fn(async (userData) => {
    const existingUser = users.find((user) => user.email === userData.email);

    if (existingUser) {
      const error = new Error('Duplicate key');
      error.code = 11000;
      error.keyPattern = { email: 1 };
      throw error;
    }

    const now = new Date();
    const user = {
      _id: `user-${users.length + 1}`,
      role: 'user',
      createdAt: now,
      updatedAt: now,
      ...userData,
    };

    users.push(user);
    return user;
  }),
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

describe('POST /api/auth/register', () => {
  const validRegistration = {
    email: 'New.User@Example.COM',
    password: 'StrongPass1!',
  };

  afterEach(async () => {
    await User.deleteMany({});
    jest.clearAllMocks();
  });

  test('successfully registers a user', async () => {
    const response = await request(app)
      .post('/api/auth/register')
      .send(validRegistration)
      .expect(201);

    expect(response.body.user).toMatchObject({
      email: 'new.user@example.com',
      role: 'user',
    });
    expect(response.body.user.id).toBe('user-1');

    const storedUser = await User.findOne({ email: 'new.user@example.com' });
    expect(storedUser).not.toBeNull();
  });

  test('rejects missing email', async () => {
    const response = await request(app)
      .post('/api/auth/register')
      .send({ password: validRegistration.password })
      .expect(400);

    expect(response.body.message).toBe('Email is required');
  });

  test('rejects missing password', async () => {
    const response = await request(app)
      .post('/api/auth/register')
      .send({ email: validRegistration.email })
      .expect(400);

    expect(response.body.message).toBe('Password is required');
  });

  test('rejects invalid email', async () => {
    const response = await request(app)
      .post('/api/auth/register')
      .send({ ...validRegistration, email: 'not-an-email' })
      .expect(400);

    expect(response.body.message).toBe('Email must be a valid email address');
  });

  test.each([
    ['object', { $ne: null }],
    ['array', ['new.user@example.com']],
  ])('rejects an email supplied as an %s', async (kind, email) => {
    await request(app)
      .post('/api/auth/register')
      .send({ email, password: validRegistration.password })
      .expect(400);
  });

  test.each([
    ['object', { $ne: null }],
    ['array', [validRegistration.password]],
  ])('rejects a password supplied as an %s', async (kind, password) => {
    await request(app)
      .post('/api/auth/register')
      .send({ email: validRegistration.email, password })
      .expect(400);
  });

  test('rejects oversized email and password without truncating them', async () => {
    await request(app)
      .post('/api/auth/register')
      .send({ email: `${'a'.repeat(245)}@example.com`, password: validRegistration.password })
      .expect(400);

    await request(app)
      .post('/api/auth/register')
      .send({ email: validRegistration.email, password: `${'A1!a'.repeat(33)}` })
      .expect(400);
  });

  test('rejects a password that fails the policy', async () => {
    const response = await request(app)
      .post('/api/auth/register')
      .send({ ...validRegistration, password: 'weak' })
      .expect(400);

    expect(response.body.message).toBe('Password must be between 8 and 128 characters');
  });

  test('rejects duplicate email registration safely', async () => {
    await request(app)
      .post('/api/auth/register')
      .send(validRegistration)
      .expect(201);

    const response = await request(app)
      .post('/api/auth/register')
      .send({ ...validRegistration, email: ' new.user@example.com ' })
      .expect(409);

    expect(response.body.message).toBe('An account with this email already exists');
    expect(response.body.passwordHash).toBeUndefined();
  });

  test('stores the password as a bcrypt hash', async () => {
    await request(app)
      .post('/api/auth/register')
      .send(validRegistration)
      .expect(201);

    const storedUser = await User.findOne({ email: 'new.user@example.com' });

    expect(storedUser.passwordHash).not.toBe(validRegistration.password);
    expect(storedUser.passwordHash).toMatch(/^\$2[aby]\$\d{2}\$/);

    const passwordMatchesHash = await bcrypt.compare(
      validRegistration.password,
      storedUser.passwordHash
    );
    expect(passwordMatchesHash).toBe(true);
  });

  test('does not return passwordHash in the response', async () => {
    const response = await request(app)
      .post('/api/auth/register')
      .send(validRegistration)
      .expect(201);

    expect(response.body.passwordHash).toBeUndefined();
    expect(response.body.user.passwordHash).toBeUndefined();
  });
});
