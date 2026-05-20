const { clearCookie } = require('./_jwt');

module.exports = function handler(req, res) {
  res.setHeader('Set-Cookie', clearCookie());
  res.redirect(302, '/api/login');
};
