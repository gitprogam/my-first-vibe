const crypto = require('crypto');

function verifyJWT(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [h, b, s] = parts;
  const expected = crypto.createHmac('sha256', secret).update(`${h}.${b}`).digest('base64url');
  if (!crypto.timingSafeEqual(Buffer.from(s), Buffer.from(expected))) return null;
  const payload = JSON.parse(Buffer.from(b, 'base64url').toString());
  if (payload.exp < Date.now() / 1000) return null;
  return payload;
}

function parseCookies(header) {
  return Object.fromEntries(
    (header || '').split(';').map(c => {
      const [k, ...v] = c.trim().split('=');
      return [k.trim(), v.join('=')];
    })
  );
}

module.exports = function handler(req, res) {
  const cookies = parseCookies(req.headers.cookie);
  const payload = cookies.session ? verifyJWT(cookies.session, process.env.JWT_SECRET) : null;
  if (!payload) return res.status(401).json({ error: 'Unauthorized' });
  res.json({ email: payload.email });
};
