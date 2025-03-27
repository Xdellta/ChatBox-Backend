const HttpError = require('../utils/HttpError');
const patterns = require('../utils/patterns');
const prisma = require('../../prisma/prismaClient');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Login
async function login(req, res, next) {
  const { email, password } = req.body;

  // Validate inputs
  if (!email || !password) {
    return next(new HttpError(400, 'Email and password are required.', null, req));
  }

  if (!patterns.email.test(email)) {
    return next(new HttpError(400, 'Invalid email format.', null, req));
  }

  if (!patterns.password.test(password)) {
    return next(new HttpError(400, 'Invalid password format.', null, req));
  }

  try {
    // Find user by email and compare password
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user || !(await bcrypt.compare(password, user.hashed_password))) {
      return next(new HttpError(400, 'Invalid email or password.', null, req));
    }

    // Generate JWT token
    const accessToken = jwt.sign({ userId: user.id }, process.env.JWT_ACCESS_SECRET, {
      expiresIn: process.env.ACCESS_EXPIRATION,
    });
    const refreshToken = jwt.sign({ userId: user.id }, process.env.JWT_REFRESH_SECRET, {
      expiresIn: process.env.REFRESH_EXPIRATION,
    });

    
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      sameSite: 'Strict',
      maxAge: parseInt(process.env.REFRESH_EXPIRATION) * 1000,
    });

    res.setHeader('Authorization', `Bearer ${accessToken}`);
    res.status(200).json({ message: 'Login successful.' });
  } catch (error) {
    return next(new HttpError(500, 'An error occurred while processing the login request.', error.message, req));
  }
}

// Register
async function register(req, res, next) {
  const { username, email, password } = req.body;

  // Validate inputs
  if (!username || !email || !password) {
    return next(new HttpError(400, 'Username, email and password are required.', null, req));
  }

  if (!patterns.username.test(username)) {
    return next(new HttpError(400, 'Invalid username format.', null, req));
  }

  if (!patterns.email.test(email)) {
    return next(new HttpError(400, 'Invalid email format.', null, req));
  }

  if (!patterns.password.test(password)) {
    return next(new HttpError(400, 'Invalid password format.', null, req));
  }

  try {
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return next(new HttpError(400, 'A user with this email already exists.', null, req));
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await prisma.user.create({
      data: {
        username,
        email,
        hashed_password: hashedPassword,
      }
    });

    // Generate JWT token
    const accessToken = jwt.sign({ userId: newUser.id }, process.env.JWT_ACCESS_SECRET, {
      expiresIn: process.env.ACCESS_EXPIRATION,
    });
    const refreshToken = jwt.sign({ userId: newUser.id }, process.env.JWT_REFRESH_SECRET, {
      expiresIn: process.env.REFRESH_EXPIRATION,
    });

    
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      sameSite: 'Strict',
      maxAge: parseInt(process.env.REFRESH_EXPIRATION) * 1000,
    });

    res.setHeader('Authorization', `Bearer ${accessToken}`);
    res.status(200).json({ message: 'Register successful.' });
  } catch (error) {
    return next(new HttpError(500, 'An error occurred while processing the register request.', error.message, req));
  }
}

// Refresh token JWT
async function refreshToken(req, res, next) {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return next(new HttpError(401, 'Unauthorized.', 'No refresh token', req));
  }

  if (!process.env.JWT_REFRESH_SECRET || !process.env.JWT_ACCESS_SECRET || !process.env.ACCESS_EXPIRATION) {
    return next(new HttpError(500, 'Incorrect server configuration.', 'Missing environment variables', req));
  }

  try {
    // Sprawdzić w bazie danych czy refresh token jest na czarnej liście

    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);

    const accessToken = jwt.sign({ userId: decoded.userId }, process.env.JWT_ACCESS_SECRET, {
      expiresIn: process.env.ACCESS_EXPIRATION,
    });

    res.setHeader('Authorization', `Bearer ${accessToken}`);
    res.status(200).json({ message: 'Token refreshed.' });
  } catch (error) {
    if (error.name === 'JsonWebTokenError' || error.name === 'TokenExpiredError') {
      return next(new HttpError(401, 'Unauthorized.', error.message, req));
    }

    return next(new HttpError(500, 'An error occurred while processing the refresh token request.', error.message, req));
  }
}

module.exports = { login, register, refreshToken };