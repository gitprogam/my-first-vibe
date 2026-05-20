module.exports = function handler(req, res) {
  const proto = req.headers['x-forwarded-proto'] || 'https';
  const host  = req.headers['host'];
  const redirectUri = `${proto}://${host}/api/callback`;

  const params = new URLSearchParams({
    client_id:     process.env.GOOGLE_CLIENT_ID,
    redirect_uri:  redirectUri,
    response_type: 'code',
    scope:         'openid email profile',
    prompt:        'select_account',
  });

  res.redirect(302, `https://accounts.google.com/o/oauth2/v2/auth?${params}`);
};
