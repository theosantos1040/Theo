import { send, getSession, readJson, normalize, generateKeyRecord, kvGet, kvSet, planThresholds, reqId } from '../_lib.js';
const allowed = new Set(['BASIC','PRO','ENTERPRISE']);
export default async function handler(req, res) {
  const requestId = reqId(req);
  const session = await getSession(req);
  if (!session) return send(res, 401, { ok: false, error: 'unauthorized', requestId });
  const storeKey = `userkeys:${session.userId}`;
  if (req.method === 'GET') {
    return send(res, 200, { ok: true, items: (await kvGet(storeKey)) || [], requestId });
  }
  if (req.method !== 'POST') return send(res, 405, { ok: false, error: 'method-not-allowed', requestId });
  if (req.headers['x-csrf-token'] !== session.csrf) return send(res, 403, { ok: false, error: 'csrf', requestId });
  const body = await readJson(req);
  const label = normalize(body?.label || 'Minha key', 120);
  const plan = String(body?.plan || 'BASIC').toUpperCase();
  if (!allowed.has(plan)) return send(res, 400, { ok: false, error: 'invalid-plan', requestId });
  const item = { ...generateKeyRecord(label, session.username, plan), thresholds: planThresholds(plan) };
  const items = (await kvGet(storeKey)) || [];
  items.unshift(item);
  await kvSet(storeKey, items);
  await kvSet(`publickey:${item.publicId}`, { userId: session.userId, plan, secret: item.secret, label });
  send(res, 201, { ok: true, item, requestId });
}
