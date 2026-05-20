const crypto = require('crypto');

const SESSION_TTL = 60 * 60 * 24; // 24시간 (초)

function signJWT(payload, secret) {
  const h = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const b = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const s = crypto.createHmac('sha256', secret).update(`${h}.${b}`).digest('base64url');
  return `${h}.${b}.${s}`;
}

function verifyJWT(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [h, b, s] = parts;

    const expected = crypto.createHmac('sha256', secret).update(`${h}.${b}`).digest('base64url');
    const sBuf = Buffer.from(s);
    const eBuf = Buffer.from(expected);
    if (sBuf.length !== eBuf.length) return null;
    if (!crypto.timingSafeEqual(sBuf, eBuf)) return null;

    const payload = JSON.parse(Buffer.from(b, 'base64url').toString('utf8'));
    if (!payload.exp || payload.exp < Date.now() / 1000) return null;
    return payload;
  } catch {
    return null;
  }
}

function parseCookies(header) {
  if (!header) return {};
  return Object.fromEntries(
    header.split(';').map(c => {
      const eq = c.indexOf('=');
      return eq === -1 ? [c.trim(), ''] : [c.slice(0, eq).trim(), c.slice(eq + 1).trim()];
    })
  );
}

function sessionCookie(jwt) {
  return `session=${jwt}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL}`;
}

function clearCookie() {
  return 'session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0';
}

module.exports = { signJWT, verifyJWT, parseCookies, sessionCookie, clearCookie, SESSION_TTL };
