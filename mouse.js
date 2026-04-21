import crypto from 'node:crypto';
import { kvSet, send } from '../_lib.js';
export default async function handler(req, res) {
  if (req.method !== 'GET') return send(res, 405, { ok: false, error: 'method-not-allowed' });
  const challengeId = crypto.randomUUID();
  const nonce = crypto.randomBytes(16).toString('hex');
  await kvSet(`mouse:${challengeId}`, { nonce, expiresAt: Date.now() + 300000 }, 300);
  send(res, 200, { ok: true, challengeId, nonce, expiresAt: Date.now() + 300000 });
}
