const { Redis } = require('@upstash/redis');
const { verifyJWT, parseCookies } = require('./_jwt');

const redis = new Redis({
  url:   process.env.KV_REST_API_URL,
  token: process.env.KV_REST_API_TOKEN,
});

function getUser(req) {
  const cookies = parseCookies(req.headers.cookie);
  return cookies.session ? verifyJWT(cookies.session, process.env.JWT_SECRET) : null;
}

function key(email) {
  return `todos:${email}`;
}

module.exports = async function handler(req, res) {
  const user = getUser(req);
  if (!user) return res.status(401).json({ error: 'Unauthorized' });

  if (req.method === 'GET') {
    const todos = await redis.get(key(user.email)) || [];
    return res.json(todos);
  }

  if (req.method === 'PUT') {
    const { todos } = req.body || {};
    if (!Array.isArray(todos)) return res.status(400).json({ error: 'todos must be an array' });
    await redis.set(key(user.email), todos);
    return res.json({ ok: true });
  }

  res.setHeader('Allow', 'GET, PUT');
  res.status(405).json({ error: 'Method not allowed' });
};
