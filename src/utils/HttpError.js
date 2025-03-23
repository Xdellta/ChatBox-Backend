class HttpError extends Error {
  constructor(status, message, devMessage, req = null) {
    super(message);
    this.status = status;
    this.devMessage = devMessage;

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
