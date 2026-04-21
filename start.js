import { send, readJson, kvGet, computeTelemetryRisk, planThresholds, signToken, reqId, rateLimit } from '../_lib.js';
export default async function handler(req, res) {
  const requestId = reqId(req);
  if (req.method !== 'POST') return send(res, 405, { ok: false, error: 'method-not-allowed', requestId });
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
  const rl = await rateLimit(`clientstart:${ip}`, 60, 60);
  if (!rl.ok) return send(res, 429, { ok: false, error: 'rate-limited', requestId });
  const body = await readJson(req);
  if (!body?.publicKey) return send(res, 400, { ok: false, error: 'missing-public-key', requestId });
  const meta = await kvGet(`publickey:${body.publicKey}`);
  if (!meta) return send(res, 404, { ok: false, error: 'unknown-public-key', requestId });
  const risk = computeTelemetryRisk(body.telemetry || {});
  const th = planThresholds(meta.plan);
  let action = 'ALLOW';
  if (risk >= th.blockAt) action = 'BLOCK';
  else if (risk >= th.challengeAt) action = 'CHALLENGE';
  const token = signToken({ publicKey: body.publicKey, plan: meta.plan, risk, action, exp: Date.now() + 120000 });
  send(res, 200, { ok: true, action, risk, token, plan: meta.plan, requestId });
}
