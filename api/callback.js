const crypto = require('crypto');

function makeJWT(payload, secret) {
  const h = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const b = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const s = crypto.createHmac('sha256', secret).update(`${h}.${b}`).digest('base64url');
  return `${h}.${b}.${s}`;
}

module.exports = async function handler(req, res) {
  const { code } = req.query;
  if (!code) return res.status(400).send('Missing code');

  const proto = req.headers['x-forwarded-proto'] || 'https';
  const host  = req.headers['host'];
  const redirectUri = `${proto}://${host}/api/callback`;

  // 코드 → 액세스 토큰 교환
  const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id:     process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uri:  redirectUri,
      grant_type:    'authorization_code',
    }),
  });

  const tokens = await tokenRes.json();
  if (!tokens.access_token) {
    return res.status(400).send('Token exchange failed');
  }

  // 사용자 이메일 확인
  const userRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  });
  const user = await userRes.json();
  const email = user.email;

  if (!email) return res.status(400).send('Cannot get email');

  // 허용 이메일 확인
  const allowed = (process.env.ALLOWED_EMAILS || '').split(',').map(e => e.trim()).filter(Boolean);
  if (allowed.length && !allowed.includes(email)) {
    return res.status(403).send(`Access denied: ${email} is not allowed.`);
  }

  // JWT 발급 (30일)
  const jwt = makeJWT(
    { email, exp: Math.floor(Date.now() / 1000) + 86400 * 30 },
    process.env.JWT_SECRET
  );

  const maxAge = 86400 * 30;
  res.setHeader('Set-Cookie', `session=${jwt}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`);
  res.redirect(302, '/');
};
