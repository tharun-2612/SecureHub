const express = require('express');

const { AUTH_RATE_LIMITS } = require('./config/rateLimit');
const { createCorsMiddleware } = require('./config/cors');
const { createAuthRouter } = require('./routes/auth.routes');
const healthRoutes = require('./routes/health.routes');
const userRoutes = require('./routes/user.routes');
const { createSecurityHeaders } = require('./middleware/securityHeaders.middleware');
const {
  htmlNotFoundHandler,
  notFoundHandler,
} = require('./middleware/notFound.middleware');
const { errorHandler } = require('./middleware/error.middleware');

function createApp({ rateLimits = AUTH_RATE_LIMITS, allowedOrigins, nodeEnv } = {}) {
  const app = express();

  app.use(createSecurityHeaders());
  app.use(createCorsMiddleware({ allowedOrigins, nodeEnv }));
  app.use(express.json());

  app.use('/api/auth', createAuthRouter(rateLimits));
  app.use('/api/health', healthRoutes);
  app.use('/api/users', userRoutes);

  app.use('/api', notFoundHandler);
  app.use(htmlNotFoundHandler);
  app.use(errorHandler);

  return app;
}

const app = createApp();
app.createApp = createApp;

module.exports = app;
