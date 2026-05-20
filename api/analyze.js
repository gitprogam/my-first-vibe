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

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const cookies = parseCookies(req.headers.cookie);
  const session = cookies.session;
  if (!session || !verifyJWT(session, process.env.JWT_SECRET)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { text, fileData, mimeType } = req.body || {};
  if (!text && !fileData) return res.status(400).json({ error: 'No content' });

  const today = new Date().toISOString().slice(0, 10);
  const instruction = `오늘 날짜는 ${today}이야.
아래 내용을 분석해서 해야 할 일 목록을 추출해줘.
기한, 마감일, 제출일, 시험일 등이 있으면 날짜를 포함해줘.
날짜에 연도가 없으면 올해(${today.slice(0, 4)})를 사용해줘.
반드시 아래 JSON 형식으로만 응답해. 다른 설명 없이 JSON만 출력:
{"todos":[{"text":"할일 내용","dueDate":"YYYY-MM-DD"}]}
dueDate가 없으면 null.`;

  const parts = [];

  if (fileData && mimeType) {
    if (mimeType.startsWith('text/')) {
      const fileText = Buffer.from(fileData, 'base64').toString('utf-8');
      parts.push({ text: instruction + '\n\n내용:\n' + fileText + (text ? '\n\n' + text : '') });
    } else {
      parts.push({ inlineData: { mimeType, data: fileData } });
      parts.push({ text: instruction + (text ? '\n\n추가 내용:\n' + text : '') });
    }
  } else {
    parts.push({ text: instruction + '\n\n내용:\n' + text });
  }

  const model = 'gemini-2.5-flash-lite';
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${process.env.GEMINI_API_KEY}`;

  const geminiRes = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ contents: [{ parts }], generationConfig: { maxOutputTokens: 1024 } }),
  });

  if (!geminiRes.ok) {
    const err = await geminiRes.json().catch(() => ({}));
    return res.status(502).json({ error: err.error?.message || 'Gemini API error' });
  }

  const data = await geminiRes.json();
  const raw  = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
  const match = raw.match(/\{[\s\S]*\}/);
  if (!match) return res.status(502).json({ error: '응답 파싱 실패' });

  res.json(JSON.parse(match[0]));
};
