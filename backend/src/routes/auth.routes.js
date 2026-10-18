const express = require('express');

const { login, register } = require('../controllers/auth.controller');
const { AUTH_RATE_LIMITS, createRateLimiter } = require('../config/rateLimit');

function createAuthRouter(rateLimits = AUTH_RATE_LIMITS) {
  const router = express.Router();

  router.post('/register', createRateLimiter(rateLimits.register), register);
  router.post('/login', createRateLimiter(rateLimits.login), login);

  return router;
}

module.exports = { createAuthRouter };
