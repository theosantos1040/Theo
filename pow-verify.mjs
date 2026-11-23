import { json, strictJson, clientIp, getSecurityStore, sha256Hex, maybeSendToSiem } from "./_shared.mjs";

export default async (req) => {
  if (req.method !== "POST") return json({ ok: false, error: "method-not-allowed" }, 405);
  const body = await strictJson(req);
  if (!body) return json({ ok: false, error: "bad-json" }, 400);

  const store = await getSecurityStore();
  const state = await store.getJSON(`pow:${body.challengeId}`);
  if (!state) return json({ ok: false, error: "unknown-challenge" }, 404);
  if (Date.now() > state.expiresAt) return json({ ok: false, error: "expired" }, 410);
  if (clientIp(req) !== state.ip) return json({ ok: false, error: "ip-mismatch" }, 403);

  const nonce = String(body.nonce || "");
  const digest = sha256Hex(`${state.salt}:${nonce}`);
  const ok = digest.startsWith("0".repeat(Number(state.difficulty || 4)));
  if (!ok) return json({ ok: false, error: "invalid-proof" }, 403);

  await store.setJSON(`pow:pass:${state.ip}:${body.challengeId}`, { ok: true, ts: Date.now() });
  await maybeSendToSiem({ type: "pow_verified", ip: state.ip, challengeId: body.challengeId, difficulty: state.difficulty });
  return json({ ok: true, proof: digest });
};
