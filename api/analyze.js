const { verifyJWT, parseCookies } = require('./_jwt');

const MAX_TEXT_LEN  = 20_000;   // 문자
const MAX_FILE_BYTES = 4 * 1024 * 1024; // 4MB (base64 디코딩 전)
const ALLOWED_MIME  = new Set([
  'image/jpeg', 'image/png', 'image/gif', 'image/webp',
  'application/pdf',
  'text/plain', 'text/markdown',
]);

function authGuard(req) {
  const cookies = parseCookies(req.headers.cookie);
  return cookies.session ? verifyJWT(cookies.session, process.env.JWT_SECRET) : null;
}

function validateInput({ text, fileData, mimeType }) {
  if (!text && !fileData) return 'text 또는 fileData가 필요합니다.';
  if (text && typeof text !== 'string') return 'text는 문자열이어야 합니다.';
  if (text && text.length > MAX_TEXT_LEN) return `텍스트가 너무 깁니다 (최대 ${MAX_TEXT_LEN}자).`;
  if (fileData) {
    if (typeof fileData !== 'string') return 'fileData는 base64 문자열이어야 합니다.';
    if (fileData.length > MAX_FILE_BYTES) return '파일이 너무 큽니다 (최대 3MB).';
    if (!mimeType || !ALLOWED_MIME.has(mimeType)) return `지원하지 않는 파일 형식입니다: ${mimeType}`;
  }
  return null;
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Defense-in-depth: 미들웨어 통과해도 API 레벨에서도 인증 재확인
  if (!authGuard(req)) return res.status(401).json({ error: 'Unauthorized' });

  const { text = '', fileData = null, mimeType = null } = req.body || {};

  const validationError = validateInput({ text, fileData, mimeType });
  if (validationError) return res.status(400).json({ error: validationError });

  const today = new Date().toISOString().slice(0, 10);
  const year  = today.slice(0, 4);
  const instruction = `오늘 날짜는 ${today}이야.
아래 내용을 분석해서 해야 할 일 목록을 추출해줘.
기한, 마감일, 제출일, 시험일, 미팅 등 날짜 정보가 있으면 반드시 포함해줘.
'5월 23일'처럼 연도가 없으면 ${year}년으로 처리해줘.
반드시 아래 JSON만 출력해. 다른 텍스트, 마크다운 코드블록 없이:
{"todos":[{"text":"할일 내용","dueDate":"YYYY-MM-DD"}]}
dueDate가 없으면 null.`;

  const parts = [];

  if (fileData && mimeType) {
    if (mimeType.startsWith('text/')) {
      const fileText = Buffer.from(fileData, 'base64').toString('utf8');
      parts.push({ text: instruction + '\n\n내용:\n' + fileText + (text ? '\n\n추가:\n' + text : '') });
    } else {
      parts.push({ inlineData: { mimeType, data: fileData } });
      parts.push({ text: instruction + (text ? '\n\n추가 내용:\n' + text : '') });
    }
  } else {
    parts.push({ text: instruction + '\n\n내용:\n' + text });
  }

  const model = 'gemini-2.5-flash-lite';
  const url   = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${process.env.GEMINI_API_KEY}`;

  let geminiData;
  try {
    const geminiRes = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ contents: [{ parts }], generationConfig: { maxOutputTokens: 1024 } }),
    });

    if (!geminiRes.ok) {
      const err = await geminiRes.json().catch(() => ({}));
      return res.status(502).json({ error: err.error?.message || 'AI 서비스 오류' });
    }

    geminiData = await geminiRes.json();
  } catch {
    return res.status(502).json({ error: 'AI 서비스에 연결할 수 없습니다.' });
  }

  const raw   = geminiData.candidates?.[0]?.content?.parts?.[0]?.text || '';
  const match = raw.match(/\{[\s\S]*\}/);
  if (!match) return res.status(502).json({ error: '응답 파싱 실패. 다시 시도해주세요.' });

  try {
    res.json(JSON.parse(match[0]));
  } catch {
    res.status(502).json({ error: '응답 JSON 파싱 실패' });
  }
};
