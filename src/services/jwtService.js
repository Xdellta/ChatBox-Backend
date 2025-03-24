const jwt = require('jsonwebtoken');

function generateToken(userId, secret, expiresIn) {
  if (!userId) {
    throw new Error('User ID is required to generate JWT.');
  }

  if (!secret) {
    throw new Error('Secret key is required to generate JWT.');
  }

  if (!expiresIn) {
    throw new Error('Expiration time is required to generate JWT.');
  }

  try {
    const token = jwt.sign({ userId }, secret, { expiresIn });
    return token;
  } catch (error) {
    throw new Error(`Error generating token: ${error.message}`);
  }
}


function decodedToken(secret, token) {
  if (!secret) {
    throw new Error('Secret key is required to decode JWT.');
  }

  if (!token) {
    throw new Error('Token is required to decode.');
  }

  try {
    const decoded = jwt.verify(token, secret);
    return decoded;
  } catch (error) {
    throw new Error(`Error decoding token: ${error.message}`);
  }
}

module.exports = { generateToken, decodedToken };