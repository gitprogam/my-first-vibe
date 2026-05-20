const { verifyJWT, parseCookies } = require('./_jwt');

module.exports = function handler(req, res) {
  const cookies = parseCookies(req.headers.cookie);
  const payload = cookies.session ? verifyJWT(cookies.session, process.env.JWT_SECRET) : null;
  if (!payload) return res.status(401).json({ error: 'Unauthorized' });
  res.json({ email: payload.email });
};
