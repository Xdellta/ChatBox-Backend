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
    if (!process.env.JWT_SECRET) {
      return next(new HttpError(500, 'Server configuration error. Please contact support.', req));
    }    

    const accessToken = jwt.sign({ userId: user.user_id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign({ userId: user.user_id }, process.env.JWT_SECRET, { expiresIn: '30d' });

    // Successful login
    res.setHeader('Authorization', `Bearer ${accessToken}`);
    res.setHeader('X-Refresh-Token', refreshToken);
    res.status(200).json({ message: 'Login successful.' });
  } catch (error) {
    return next(new HttpError(500, 'An error occurred while processing the login request.', req));
  }
}


// Register
async function register(req, res, next) {
  const { username, email, password } = req.body;

  // Validate inputs
  if (!username || !email || !password) {
    return next(new HttpError(400, 'Username, email and password are required.', req));
  }

  if (!patterns.username.test(username)) {
    return next(new HttpError(400, 'Invalid username format.', req));
  }

  if (!patterns.email.test(email)) {
    return next(new HttpError(400, 'Invalid email format.', req));
  }

  if (!patterns.password.test(password)) {
    return next(new HttpError(400, 'Invalid password format.', req));
  }

  try {
    const existingUser = await prisma.user.findUnique({ where: { email } });
    if (existingUser) {
      return next(new HttpError(400, 'A user with this email already exists.', req));
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
    if (!process.env.JWT_SECRET) {
      return next(new HttpError(500, 'Server configuration error. Please contact support.', req));
    }    

    const accessToken = jwt.sign({ userId: newUser.user_id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign({ userId: newUser.user_id }, process.env.JWT_SECRET, { expiresIn: '30d' });

    res.setHeader('Authorization', `Bearer ${accessToken}`);
    res.setHeader('X-Refresh-Token', refreshToken);
    res.status(200).json({ message: 'Register successful.' });
  } catch (error) {
    return next(new HttpError(500, 'An error occurred while processing the register request.', req));
  }
}


module.exports = { login, register };