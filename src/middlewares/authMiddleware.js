const HttpError = require('../utils/HttpError');
const jwt = require('jsonwebtoken');

async function verifyAccess(req, res, next) {
  const accessToken = req.headers.authorization?.replace(/^Bearer\s/, '');

  if (!accessToken) {
    return next(new HttpError(401, 'Unauthorized.', 'No access token provided', req));
  }

  try {
    const decoded = jwt.verify(accessToken, process.env.JWT_ACCESS_SECRET);
    
    req.user = decoded;
    next();

  } catch (error) {
    if (error.name === 'TokenExpiredError' || error.name === 'JsonWebTokenError') {
      return next(new HttpError(401, 'Unauthorized', error.message, req));
    }

    return next(new HttpError(500, 'Internal Server Error', 'Error verifying access token.', req));
  }
}

module.exports = { verifyAccess };