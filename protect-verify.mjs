import { json, strictJson, getSecurityStore, serviceTokenVerify, planThresholds } from "./_shared.mjs";
import { inspectStrings } from "./_waf.mjs";

export default async (req) => {
  if (req.method !== "POST") return json({ ok: false, error: "method-not-allowed" }, 405);
  const body = await strictJson(req);
  if (!body) return json({ ok: false, error: "bad-json" }, 400);

  const secretKey = typeof body.secretKey === "string" ? body.secretKey.slice(0, 128) : "";
  const token = typeof body.token === "string" ? body.token : "";
  const findings = inspectStrings([secretKey]);
  if (!secretKey || !token || findings.length) return json({ ok: false, error: "invalid-input" }, 400);

  const payload = serviceTokenVerify(token);
  if (!payload) return json({ ok: false, error: "invalid-token" }, 403);

  const store = await getSecurityStore();
  const keyMeta = await store.getJSON(`publickey:${payload.publicKey}`);
  if (!keyMeta) return json({ ok: false, error: "unknown-public-key" }, 404);
  if (keyMeta.secret !== secretKey) return json({ ok: false, error: "invalid-secret" }, 403);

  const thresholds = planThresholds(keyMeta.plan);
  let decision = "ALLOW";
  if (payload.risk >= thresholds.blockAt) decision = "BLOCK";
  else if (payload.risk >= thresholds.challengeAt) decision = "CHALLENGE";

  return json({ ok: true, decision, risk: payload.risk, publicKey: payload.publicKey, plan: keyMeta.plan, thresholds });
};
