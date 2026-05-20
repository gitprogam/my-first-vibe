// Edge Middleware — HTML/정적 파일이 서빙되기 전에 인증 검사
// Node.js crypto를 사용할 수 없으므로 Web Crypto API 사용

const PUBLIC_PATHS = ['/api/login', '/api/callback'];
const MAX_BODY_AGE  = 60 * 60 * 24; // 24시간

async function verifyHMAC(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [h, b, s] = parts;

    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const sigBytes  = Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const dataBytes = new TextEncoder().encode(`${h}.${b}`);

    const valid = await crypto.subtle.verify('HMAC', keyMaterial, sigBytes, dataBytes);
    if (!valid) return null;

    const payload = JSON.parse(atob(b.replace(/-/g, '+').replace(/_/g, '/')));
    if (!payload.exp || payload.exp < Date.now() / 1000) return null;
    return payload;
  } catch {
    return null;
  }
}

function getSessionCookie(req) {
  const header = req.headers.get('cookie') || '';
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim();
    if (key === 'session') return part.slice(eq + 1).trim();
  }
  return null;
}

export default async function middleware(req) {
  const { pathname } = new URL(req.url);

  // 공개 경로는 통과
  if (PUBLIC_PATHS.some(p => pathname === p || pathname.startsWith(p + '?'))) {
    return;
  }

  const secret = process.env.JWT_SECRET;
  if (!secret) {
    // 서버 설정 오류 — 안전하게 차단
    return new Response('Server misconfiguration', { status: 500 });
  }

  const token   = getSessionCookie(req);
  const payload = token ? await verifyHMAC(token, secret) : null;

  if (!payload) {
    return Response.redirect(new URL('/api/login', req.url), 302);
  }

  // 인증 통과 — 원본 요청 계속
}

export const config = {
  matcher: ['/((?!_next/|favicon\\.ico).*)'],
};
