module.exports = {
  email: /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,254}$/,
  username: /^[A-Za-zÀ-ÿ\u0100-\u017F ]{3,50}$/,
  password: /(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{6,254}/,
};