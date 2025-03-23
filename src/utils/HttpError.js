class HttpError extends Error {
  constructor(status, message, req = null) {
    super(message);
    this.status = status;

    if (req) {
      this.method = req.method;
      this.url = req.originalUrl;
      this.body = req.body;
      this.headers = req.headers;
    }

    this.timestamp = new Date().toISOString();
  }
}

module.exports = HttpError;
