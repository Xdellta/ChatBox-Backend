const { generateAccessToken, generateRefreshToken } = require('../services/jwtService');
const HttpError = require('../utils/HttpError');
const patterns = require('../utils/patterns');
const prisma = require('../../prisma/prismaClient');
const bcrypt = require('bcrypt');

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
    const accessToken = generateAccessToken(user.user_id);
    const refreshToken = generateRefreshToken(user.user_id);

    if (accessToken.error) {
      return next(new HttpError(500, 'Error while generating access token.', accessToken.error, req));
    }
    
    if (refreshToken.error) {
      return next(new HttpError(500, 'Error while generating refresh token.', refreshToken.error, req));
    }

    // Successful login
    res.setHeader('Authorization', `Bearer ${accessToken}`);
    res.setHeader('X-Refresh-Token', refreshToken);
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
    const accessToken = generateAccessToken(newUser.user_id);
    const refreshToken = generateRefreshToken(newUser.user_id);

    if (accessToken.error) {
      return next(new HttpError(500, 'Error while generating access token.', accessToken.error, req));
    }

    if (refreshToken.error) {
      return next(new HttpError(500, 'Error while generating refresh token.', refreshToken.error, req));
    }

    // Successful register
    res.setHeader('Authorization', `Bearer ${accessToken}`);
    res.setHeader('X-Refresh-Token', refreshToken);
    res.status(200).json({ message: 'Register successful.' });
  } catch (error) {
    return next(new HttpError(500, 'An error occurred while processing the register request.', error.message, req));
  }
}

module.exports = { login, register };