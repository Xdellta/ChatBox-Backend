const HttpError = require('../utils/HttpError');
const patterns = require('../utils/patterns');
const prisma = require('../../prisma/prismaClient');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

async function login(req, res, next) {
  const { email, password } = req.body;

  // Validate input
  if (!email || !password) {
    return next(new HttpError(400, 'Email and password are required.', req));
  }

  if (!patterns.email.test(email)) {
    return next(new HttpError(400, 'Invalid email format.', req));
  }

  if (!patterns.password.test(password)) {
    return next(new HttpError(400, 'Invalid password format.', req));
  }

  try {
    // Find user by email and compare password
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user || !(await bcrypt.compare(password, user.hashed_password))) {
      return next(new HttpError(400, 'Invalid email or password.', req));
    }

    // Generate JWT token
    const accessToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '30d' });

    // Successful login
    res.setHeader('Authorization', `Bearer ${accessToken}`);
    res.setHeader('X-Refresh-Token', refreshToken);
    res.status(200).json({ message: 'Login successful.' });
  } catch (error) {
    return next(new HttpError(500, 'An error occurred while processing the login request.', req));
  }
}

module.exports = { login };