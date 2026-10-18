const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const User = require('../models/User');
const {
  validateLoginInput,
  validateRegistrationInput,
} = require('../validators/auth.validator');

const PASSWORD_SALT_ROUNDS = 12;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';
const INVALID_CREDENTIALS_MESSAGE = 'Invalid email or password';

function createHttpError(statusCode, message) {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
}

async function registerUser(input) {
  const { email, password } = validateRegistrationInput(input);
  const passwordHash = await bcrypt.hash(password, PASSWORD_SALT_ROUNDS);

  try {
    return await User.create({
      email,
      passwordHash,
    });
  } catch (error) {
    if (error.code === 11000 && error.keyPattern && error.keyPattern.email) {
      throw createHttpError(409, 'An account with this email already exists');
    }

    throw error;
  }
}

function getJwtSecret() {
  if (!process.env.JWT_SECRET) {
    throw createHttpError(500, 'JWT secret is not configured');
  }

  return process.env.JWT_SECRET;
}

async function loginUser(input) {
  const { email, password } = validateLoginInput(input);
  const user = await User.findOne({ email });

  if (!user) {
    throw createHttpError(401, INVALID_CREDENTIALS_MESSAGE);
  }

  const passwordMatches = await bcrypt.compare(password, user.passwordHash);

  if (!passwordMatches) {
    throw createHttpError(401, INVALID_CREDENTIALS_MESSAGE);
  }

  const token = jwt.sign(
    {
      sub: user._id.toString(),
      role: user.role,
    },
    getJwtSecret(),
    {
      expiresIn: JWT_EXPIRES_IN,
    }
  );

  return {
    token,
    user,
  };
}

module.exports = {
  loginUser,
  registerUser,
};
