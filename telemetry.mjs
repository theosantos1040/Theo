import { json, strictJson, clientIp, getSecurityStore, computeTelemetryRisk, maybeSendToSiem, sha256Hex, updateReputation } from "./_shared.mjs";
import { inspectStrings } from "./_waf.mjs";

export default async (req) => {
  if (req.method !== "POST") return json({ ok: false, error: "method-not-allowed" }, 405);
  const payload = await strictJson(req);
  if (!payload) return json({ ok: false, error: "bad-json" }, 400);

  const suspiciousFields = inspectStrings([
    payload?.ua || "",
    payload?.platform || "",
    payload?.lang || "",
    payload?.url || ""
  ]);
  const ip = clientIp(req);
  const fpKey = sha256Hex(JSON.stringify(payload.fp || {}) + "|" + (payload.ua || ""));
  const store = await getSecurityStore();
  const risk = computeTelemetryRisk(payload);
  const totalScore = Math.max(0, Math.min(1, risk.score + (suspiciousFields.length ? 0.35 : 0)));
  const rep = await updateReputation(ip, fpKey, totalScore > 0.7 ? 0.12 : -0.01);

  const record = {
    ip,
    path: payload.url || "/",
    ts: Date.now(),
    fpKey,
    score: totalScore,
    factors: { ...risk.factors, wafFindings: suspiciousFields.length },
    reputation: rep,
    summary: {
      pointerCount: payload?.behavior?.pointer?.length || 0,
      touchCount: payload?.behavior?.touch?.length || 0,
      motionCount: payload?.behavior?.motion?.length || 0,
      scrollCount: payload?.behavior?.scroll?.length || 0,
      heartbeatCount: payload?.behavior?.heartbeatCount || 0
    }
  };

  await store.setJSON(`telemetry:last:${fpKey}`, record);
  await maybeSendToSiem({ type: "telemetry_ingest", ...record });

  return json({ ok: true, score: totalScore, factors: record.factors });
};
