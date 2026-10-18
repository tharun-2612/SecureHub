const { loginUser, registerUser } = require('../services/auth.service');

async function register(req, res, next) {
  try {
    const user = await registerUser(req.body);

    res.status(201).json({
      user: {
        id: user._id.toString(),
        email: user.email,
        role: user.role,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      },
    });
  } catch (error) {
    next(error);
  }
}

async function login(req, res, next) {
  try {
    const { token, user } = await loginUser(req.body);

    res.status(200).json({
      token,
      user: {
        id: user._id.toString(),
        email: user.email,
        role: user.role,
      },
    });
  } catch (error) {
    next(error);
  }
}

module.exports = {
  login,
  register,
};
