import crypto from 'node:crypto';
import { readJson, send, normalize, verifyToken, kvGet, kvSet, passwordHash, setSession, sessionCookies, rateLimit, reqId, pushErrorLog } from '../_lib.js';
export default async function handler(req, res) {
  const requestId = reqId(req);
  if (req.method !== 'POST') return send(res, 405, { ok: false, error: 'method-not-allowed', requestId });
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  const rl = await rateLimit(`signup:${ip}`, 8, 60);
  if (!rl.ok) return send(res, 429, { ok: false, error: 'rate-limited', requestId });
  const body = await readJson(req);
  if (!body) return send(res, 400, { ok: false, error: 'bad-json', requestId });
  const name = normalize(body.name, 80);
  const email = normalize(body.email, 120).toLowerCase();
  const password = typeof body.password === 'string' ? body.password.slice(0, 200) : '';
  const termsAccepted = body.termsAccepted === true;
  const mouse = verifyToken(body.mouseToken || '');
  if (!name || !email || password.length < 8) return send(res, 400, { ok: false, error: 'invalid-input', requestId });
  if (!termsAccepted) return send(res, 400, { ok: false, error: 'terms-required', requestId });
  if (!mouse || mouse.type !== 'mouse_signup') return send(res, 400, { ok: false, error: 'mouse-challenge-required', requestId });
  const userKey = 'user:' + crypto.createHash('sha256').update(email).digest('hex');
  if (await kvGet(userKey)) return send(res, 409, { ok: false, error: 'already-exists', requestId });
  const salt = crypto.randomBytes(16).toString('hex');
  const user = { id: crypto.randomUUID(), name, email, salt, passwordHash: passwordHash(password, salt), createdAt: new Date().toISOString() };
  await kvSet(userKey, user);
  const sid = crypto.randomBytes(24).toString('base64url');
  const csrf = crypto.randomBytes(24).toString('base64url');
  await setSession(sid, { userId: user.id, username: user.email, displayName: user.name, role: 'user', csrf });
  send(res, 201, { ok: true, csrfToken: csrf, requestId }, { 'Set-Cookie': sessionCookies(sid) });
}
