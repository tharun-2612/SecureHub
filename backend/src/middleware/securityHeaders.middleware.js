const helmet = require('helmet');

function createSecurityHeaders() {
  const isProduction = process.env.NODE_ENV === 'production';

  return helmet({
    contentSecurityPolicy: false,
    frameguard: { action: 'deny' },
    hsts: isProduction
      ? { maxAge: 15_552_000, includeSubDomains: false }
      : false,
  });
}

module.exports = { createSecurityHeaders };
