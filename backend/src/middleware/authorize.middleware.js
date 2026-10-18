function validateUserId(req, res, next) {
  if (!/^[0-9a-fA-F]{24}$/.test(req.params.userId)) {
    return res.status(400).json({ message: 'userId must be a valid MongoDB ObjectId' });
  }

  return next();
}

function authorizeProfileAccess(req, res, next) {
  if (req.auth.role !== 'admin' && req.auth.userId !== req.params.userId) {
    return res.status(403).json({ message: 'Forbidden' });
  }

  return next();
}

module.exports = { authorizeProfileAccess, validateUserId };
