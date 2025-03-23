const { json } = require('express');
const statuses = require('statuses');

module.exports = function errorHandler(err, req, res, next) {
  const mode = process.env.NODE_ENV || 'development';
  const status = err.status || 500;

  const response = {
    message: err.message || statuses.message[status],
  };

  if (mode === 'development') {
    response.details = {
      status,
      method: err.method,
      url: err.url,
      body: err.body,
      headers: err.headers,
      timestamp: err.timestamp,
      stack: err.stack,
    }
  }

  console.error(response);

  res.status(status).json(response);
};