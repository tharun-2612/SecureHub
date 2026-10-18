const jwt = require('jsonwebtoken');

function unauthorized(res) {
  return res.status(401).json({ message: 'Authentication required' });
}

function authenticate(req, res, next) {
  const authorization = req.get('Authorization');
  const match = typeof authorization === 'string'
    ? authorization.match(/^Bearer ([^\s]+)$/i)
    : null;

  if (!match) {
    return unauthorized(res);
  }

  if (!process.env.JWT_SECRET) {
    return res.status(500).json({ message: 'Internal server error' });
  }

  try {
    const payload = jwt.verify(match[1], process.env.JWT_SECRET);

    if (
      !payload ||
      typeof payload !== 'object' ||
      typeof payload.sub !== 'string' ||
      !['user', 'admin'].includes(payload.role)
    ) {
      return unauthorized(res);
    }

    req.auth = {
      userId: payload.sub,
      role: payload.role,
    };
    return next();
  } catch (error) {
    return unauthorized(res);
  }
}

module.exports = { authenticate };
