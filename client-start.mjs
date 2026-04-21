import { json, strictJson, getSecurityStore, computeTelemetryRisk, planThresholds, serviceTokenSign, sha256Hex } from "./_shared.mjs";
import { inspectStrings } from "./_waf.mjs";

export default async (req) => {
  if (req.method !== "POST") return json({ ok: false, error: "method-not-allowed" }, 405);
  const body = await strictJson(req);
  if (!body) return json({ ok: false, error: "bad-json" }, 400);

  const publicKey = typeof body.publicKey === "string" ? body.publicKey.slice(0, 80) : "";
  const telemetry = body.telemetry && typeof body.telemetry === "object" ? body.telemetry : {};
  const findings = inspectStrings([publicKey, telemetry?.ua || "", telemetry?.url || ""]);
  if (!publicKey || findings.length) return json({ ok: false, error: "invalid-input" }, 400);

  const store = await getSecurityStore();
  const keyMeta = await store.getJSON(`publickey:${publicKey}`);
  if (!keyMeta) return json({ ok: false, error: "unknown-public-key" }, 404);

  const risk = computeTelemetryRisk(telemetry);
  const thresholds = planThresholds(keyMeta.plan);
  let action = "ALLOW";
  if (risk.score >= thresholds.blockAt) action = "BLOCK";
  else if (risk.score >= thresholds.challengeAt) action = "CHALLENGE";

  const token = serviceTokenSign({
    publicKey,
    userId: keyMeta.userId,
    plan: keyMeta.plan,
    risk: risk.score,
    action,
    fp: sha256Hex(JSON.stringify(telemetry?.fp || {})),
    exp: Date.now() + 2 * 60 * 1000
  });

  return json({ ok: true, action, risk: risk.score, token, plan: keyMeta.plan });
};
