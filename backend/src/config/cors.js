const cors = require('cors');

const ALLOWED_METHODS = ['GET', 'POST', 'OPTIONS'];
const ALLOWED_HEADERS = ['Authorization', 'Content-Type'];

function parseAllowedOrigins(value) {
  if (Array.isArray(value)) {
    return value.map((origin) => String(origin).trim()).filter(Boolean);
  }

  if (typeof value !== 'string') {
    return [];
  }

  return value.split(',').map((origin) => origin.trim()).filter(Boolean);
}

function createCorsMiddleware({
  allowedOrigins = process.env.CORS_ALLOWED_ORIGINS,
  nodeEnv = process.env.NODE_ENV,
} = {}) {
  const origins = parseAllowedOrigins(allowedOrigins);

  if (origins.includes('*')) {
    throw new Error('CORS_ALLOWED_ORIGINS must list explicit origins; wildcard origins are not supported');
  }

  const allowlist = new Set(origins);

  return cors({
    origin(origin, callback) {
      if (!origin) {
        return callback(null, false);
      }

      return callback(null, allowlist.has(origin));
    },
    methods: ALLOWED_METHODS,
    allowedHeaders: ALLOWED_HEADERS,
    credentials: false,
    optionsSuccessStatus: 204,
    maxAge: nodeEnv === 'production' ? 600 : undefined,
  });
}

module.exports = {
  createCorsMiddleware,
  parseAllowedOrigins,
};
