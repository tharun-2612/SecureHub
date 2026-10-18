const express = require('express');

const { getUserProfile } = require('../controllers/user.controller');
const { authenticate } = require('../middleware/authenticate.middleware');
const {
  authorizeProfileAccess,
  validateUserId,
} = require('../middleware/authorize.middleware');

const router = express.Router();

router.get('/:userId', authenticate, validateUserId, authorizeProfileAccess, getUserProfile);

module.exports = router;
