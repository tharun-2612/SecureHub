function createValidationError(message) {
  const error = new Error(message);
  error.statusCode = 400;
  return error;
}

function normalizeEmail(email) {
  return email.trim().toLowerCase();
}

const MAX_EMAIL_LENGTH = 254;
const MAX_PASSWORD_LENGTH = 128;

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validateInputObject(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw createValidationError('Request body must be an object');
  }
}

function validateEmail(email) {
  if (typeof email !== 'string') {
    throw createValidationError('Email must be a string');
  }

  if (email.length > MAX_EMAIL_LENGTH) {
    throw createValidationError(`Email must be no more than ${MAX_EMAIL_LENGTH} characters`);
  }

  const normalizedEmail = normalizeEmail(email);

  if (!normalizedEmail || !isValidEmail(normalizedEmail)) {
    throw createValidationError('Email must be a valid email address');
  }

  return normalizedEmail;
}

function validatePassword(password) {
  if (typeof password !== 'string') {
    throw createValidationError('Password must be a string');
  }

  if (password.length > MAX_PASSWORD_LENGTH) {
    throw createValidationError(`Password must be no more than ${MAX_PASSWORD_LENGTH} characters`);
  }
}

function validatePasswordPolicy(password) {
  if (password.length < 8 || password.length > MAX_PASSWORD_LENGTH) {
    return 'Password must be between 8 and 128 characters';
  }

  if (!/[a-z]/.test(password)) {
    return 'Password must include at least one lowercase letter';
  }

  if (!/[A-Z]/.test(password)) {
    return 'Password must include at least one uppercase letter';
  }

  if (!/[0-9]/.test(password)) {
    return 'Password must include at least one number';
  }

  if (!/[^A-Za-z0-9]/.test(password)) {
    return 'Password must include at least one special character';
  }

  return null;
}

function validateRegistrationInput(input = {}) {
  validateInputObject(input);
  const { email, password } = input;

  if (!email) {
    throw createValidationError('Email is required');
  }

  if (!password) {
    throw createValidationError('Password is required');
  }

  const normalizedEmail = validateEmail(email);
  validatePassword(password);

  const passwordPolicyError = validatePasswordPolicy(password);

  if (passwordPolicyError) {
    throw createValidationError(passwordPolicyError);
  }

  return {
    email: normalizedEmail,
    password,
  };
}

function validateLoginInput(input = {}) {
  validateInputObject(input);
  const { email, password } = input;

  if (!email || !password) {
    throw createValidationError('Email and password are required');
  }

  const normalizedEmail = validateEmail(email);
  validatePassword(password);

  return {
    email: normalizedEmail,
    password,
  };
}

module.exports = {
  validateRegistrationInput,
  validateLoginInput,
  normalizeEmail,
};
