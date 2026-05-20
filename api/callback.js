const { signJWT, sessionCookie, SESSION_TTL } = require('./_jwt');

module.exports = async function handler(req, res) {
  const { code, error } = req.query;

  if (error) return res.status(400).send(`Google OAuth 오류: ${error}`);
  if (!code)  return res.status(400).send('Authorization code가 없습니다.');

  const proto      = req.headers['x-forwarded-proto'] || 'https';
  const host       = req.headers['host'];
  const redirectUri = `${proto}://${host}/api/callback`;

  // 코드 → 토큰 교환
  let tokens;
  try {
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
    tokens = await tokenRes.json();
  } catch {
    return res.status(502).send('Google 서버와 통신 실패');
  }

  if (!tokens.access_token) {
    return res.status(400).send('토큰 발급 실패');
  }

  // 사용자 정보 확인
  let user;
  try {
    const userRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    user = await userRes.json();
  } catch {
    return res.status(502).send('사용자 정보 조회 실패');
  }

  const email = (user.email || '').toLowerCase().trim();
  if (!email || !user.email_verified) {
    return res.status(400).send('인증된 이메일이 없습니다.');
  }

  // 허용 이메일 검사
  const allowed = (process.env.ALLOWED_EMAILS || '')
    .split(',')
    .map(e => e.toLowerCase().trim())
    .filter(Boolean);

  if (allowed.length && !allowed.includes(email)) {
    return res.status(403).send('접근 권한이 없는 계정입니다.');
  }

  // JWT 발급 (24시간)
  const jwt = signJWT(
    { email, iat: Math.floor(Date.now() / 1000), exp: Math.floor(Date.now() / 1000) + SESSION_TTL },
    process.env.JWT_SECRET
  );

  res.setHeader('Set-Cookie', sessionCookie(jwt));
  res.redirect(302, '/');
};
