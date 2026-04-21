import crypto from 'node:crypto';
import { readJson, send, normalize, kvGet, verifyPassword, setSession, sessionCookies, rateLimit, reqId, pushErrorLog } from '../_lib.js';
export default async function handler(req, res) {
  const requestId = reqId(req);
  if (req.method !== 'POST') return send(res, 405, { ok: false, error: 'method-not-allowed', requestId });
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  const rl = await rateLimit(`login:${ip}`, 10, 60);
  if (!rl.ok) return send(res, 429, { ok: false, error: 'rate-limited', requestId });
  const body = await readJson(req);
  if (!body) return send(res, 400, { ok: false, error: 'bad-json', requestId });
  const email = normalize(body.email, 120).toLowerCase();
  const password = typeof body.password === 'string' ? body.password.slice(0, 200) : '';
  const key = 'user:' + crypto.createHash('sha256').update(email).digest('hex');
  const user = await kvGet(key);
  if (!user || !verifyPassword(password, user.salt, user.passwordHash)) {
    return send(res, 401, { ok: false, error: 'invalid-credentials', requestId });
  }
  const sid = crypto.randomBytes(24).toString('base64url');
  const csrf = crypto.randomBytes(24).toString('base64url');
  await setSession(sid, { userId: user.id, username: user.email, displayName: user.name, role: 'user', csrf });
  send(res, 200, { ok: true, csrfToken: csrf, requestId }, { 'Set-Cookie': sessionCookies(sid) });
}
