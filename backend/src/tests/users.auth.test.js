const jwt = require('jsonwebtoken');
const request = require('supertest');

const users = [];

jest.mock('../models/User', () => ({
  findById: jest.fn(async (userId) => users.find((user) => user._id === userId) || null),
}));

const { createApp } = require('../app');
const User = require('../models/User');
const app = createApp({
  rateLimits: {
    login: { windowMs: 60_000, limit: 10_000 },
    register: { windowMs: 60_000, limit: 10_000 },
  },
});

describe('GET /api/users/:userId', () => {
  const jwtSecret = 'test-users-jwt-secret';
  const ownId = '507f1f77bcf86cd799439011';
  const otherId = '507f1f77bcf86cd799439012';
  const passwordHash = '$2b$12$test-hash-that-must-never-be-returned';

  function createToken(claims, options) {
    return jwt.sign(claims, jwtSecret, options);
  }

  function getProfile(userId, token) {
    return request(app)
      .get(`/api/users/${userId}`)
      .set('Authorization', `Bearer ${token}`);
  }

  beforeAll(() => {
    process.env.JWT_SECRET = jwtSecret;
  });

  beforeEach(() => {
    users.push(
      {
        _id: ownId,
        email: 'own@example.com',
        role: 'user',
        createdAt: new Date('2026-01-01T00:00:00.000Z'),
        updatedAt: new Date('2026-01-02T00:00:00.000Z'),
        passwordHash,
      },
      {
        _id: otherId,
        email: 'other@example.com',
        role: 'user',
        createdAt: new Date('2026-01-01T00:00:00.000Z'),
        updatedAt: new Date('2026-01-02T00:00:00.000Z'),
        passwordHash,
      }
    );
  });

  afterEach(() => {
    users.length = 0;
    jest.clearAllMocks();
  });

  test('rejects a missing Authorization header', async () => {
    const response = await request(app).get(`/api/users/${ownId}`).expect(401);
    expect(response.body.message).toBe('Authentication required');
  });

  test('rejects a malformed Bearer token', async () => {
    await request(app)
      .get(`/api/users/${ownId}`)
      .set('Authorization', 'Bearer first second')
      .expect(401);
  });

  test('rejects an invalid JWT', async () => {
    await getProfile(ownId, 'not.a.valid.jwt').expect(401);
  });

  test('rejects an expired JWT', async () => {
    const token = createToken({ sub: ownId, role: 'user' }, { expiresIn: -1 });
    await getProfile(ownId, token).expect(401);
  });

  test.each(['not-an-object-id', '123456789012', '$ne'])('rejects malformed userId %s before querying', async (userId) => {
    const token = createToken({ sub: ownId, role: 'user' });
    await getProfile(userId, token).expect(400);
    expect(User.findById).not.toHaveBeenCalled();
  });

  test('allows a user to access their own profile and omits authentication data', async () => {
    const token = createToken({ sub: ownId, role: 'user' });
    const response = await getProfile(ownId, token).expect(200);

    expect(response.body.user).toEqual({
      id: ownId,
      email: 'own@example.com',
      role: 'user',
      createdAt: '2026-01-01T00:00:00.000Z',
      updatedAt: '2026-01-02T00:00:00.000Z',
    });
    expect(JSON.stringify(response.body)).not.toContain(passwordHash);
    expect(response.body.user.passwordHash).toBeUndefined();
  });

  test('forbids a user from accessing another user profile', async () => {
    const token = createToken({ sub: ownId, role: 'user' });
    await getProfile(otherId, token).expect(403);
  });

  test('allows an admin to access another user profile', async () => {
    const token = createToken({ sub: ownId, role: 'admin' });
    const response = await getProfile(otherId, token).expect(200);

    expect(response.body.user.email).toBe('other@example.com');
    expect(JSON.stringify(response.body)).not.toContain(passwordHash);
  });

  test('does not trust user ID or role values from body or query parameters', async () => {
    const token = createToken({ sub: ownId, role: 'user' });
    await request(app)
      .get(`/api/users/${otherId}?role=admin&userId=${otherId}`)
      .set('Authorization', `Bearer ${token}`)
      .send({ role: 'admin', userId: otherId })
      .expect(403);

    expect(User.findById).not.toHaveBeenCalled();
  });
});
