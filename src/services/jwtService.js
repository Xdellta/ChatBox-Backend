const jwt = require('jsonwebtoken');

function generateAccessToken(userId) {
  if (!userId) {
    throw new Error('User ID is required to generate the access token.');
  }

  if (!process.env.JWT_ACCESS_SECRET) {
    throw new Error('JWT access secret is missing in environment variables.');
  }

  const accessToken = jwt.sign({ userId }, process.env.JWT_ACCESS_SECRET, { expiresIn: '1h' });
  return accessToken;
}


function generateRefreshToken(userId) {
  if (!userId) {
    throw new Error('User ID is required to generate the access token.');
  }

  if (!process.env.JWT_REFRESH_SECRET) {
    throw new Error('JWT refresh secret is missing in environment variables.');
  }

  const refreshToken = jwt.sign({ userId }, process.env.JWT_REFRESH_SECRET, { expiresIn: '30d' });
  return refreshToken;
}

module.exports = { generateAccessToken, generateRefreshToken };