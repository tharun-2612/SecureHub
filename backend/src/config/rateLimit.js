const rateLimit = require('express-rate-limit');

const AUTH_RATE_LIMITS = Object.freeze({
  login: Object.freeze({
    windowMs: 15 * 60 * 1000,
    limit: 10,
  }),
  register: Object.freeze({
    windowMs: 60 * 60 * 1000,
    limit: 5,
  }),
});

function createRateLimiter({ windowMs, limit }) {
  return rateLimit({
    windowMs,
    limit,
    standardHeaders: true,
    legacyHeaders: false,
    handler(req, res) {
      return res.status(429).json({ message: 'Too many requests. Please try again later.' });
    },
  });
}

module.exports = {
  AUTH_RATE_LIMITS,
  createRateLimiter,
};
