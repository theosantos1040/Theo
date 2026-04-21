import { kvGet, send, readJson, signToken } from '../_lib.js';
export default async function handler(req, res) {
  if (req.method !== 'POST') return send(res, 405, { ok: false, error: 'method-not-allowed' });
  const body = await readJson(req);
  if (!body) return send(res, 400, { ok: false, error: 'bad-json' });
  const entry = await kvGet(`mouse:${body.challengeId}`);
  if (!entry || Date.now() > entry.expiresAt) return send(res, 410, { ok: false, error: 'expired' });
  const stats = body.stats || {};
  const passed = Number(stats.moves || 0) >= 12 && Number(stats.distance || 0) >= 220 && Number(stats.duration || 0) >= 1200;
  if (!passed) return send(res, 403, { ok: false, error: 'mouse-challenge-failed' });
  send(res, 200, { ok: true, token: signToken({ type: 'mouse_signup', exp: Date.now() + 600000 }) });
}
