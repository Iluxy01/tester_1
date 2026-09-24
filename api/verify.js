// Vercel serverless-функция. Переменная окружения BOT_TOKEN задаётся в настройках проекта Vercel.
const crypto = require('crypto');

module.exports = (req, res) => {
  const token = process.env.BOT_TOKEN;
  const p = new URLSearchParams(req.headers['x-init-data'] || '');
  const hash = p.get('hash');
  if (!token || !hash) return res.status(401).json({ ok: false });
  p.delete('hash');

  const dataCheckString = [...p.entries()].map(([k, v]) => `${k}=${v}`).sort().join('\n');
  const secret = crypto.createHmac('sha256', 'WebAppData').update(token).digest();
  const calc = crypto.createHmac('sha256', secret).update(dataCheckString).digest('hex');

  const a = Buffer.from(calc), b = Buffer.from(hash);
  const fresh = Date.now() / 1000 - Number(p.get('auth_date')) < 3600;
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b) || !fresh)
    return res.status(401).json({ ok: false });

  const user = JSON.parse(p.get('user') || '{}');
  res.status(200).json({ ok: true, id: user.id, name: user.first_name });
};
