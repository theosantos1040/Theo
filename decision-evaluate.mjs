import { json, strictJson, clientIp, sha256Hex, getSecurityStore, getReputation, verifyPreclearanceToken } from "./_shared.mjs";

export default async (req) => {
  if (req.method !== "POST") return json({ ok: false, error: "method-not-allowed" }, 405);
  const body = await strictJson(req);
  if (!body) return json({ ok: false, error: "bad-json" }, 400);

  const ip = clientIp(req);
  const fpKey = sha256Hex(JSON.stringify(body.fp || {}) + "|" + (body.ua || ""));
  const store = await getSecurityStore();
  const lastTelemetry = await store.getJSON(`telemetry:last:${fpKey}`);
  const reputation = await getReputation(ip, fpKey);

  const powPassed = !!(body.powChallengeId && await store.getJSON(`pow:pass:${ip}:${body.powChallengeId}`));
  const preclearance = verifyPreclearanceToken(body.preclearanceToken || "");
  const telemetryScore = Number(lastTelemetry?.score || 0);
  const repScore = Math.max(Number(reputation.ip.score || 0), Number(reputation.fp.score || 0));
  const effective = Math.max(0, Math.min(1, telemetryScore + Math.max(0, repScore)));

  let action = "ALLOW";
  let reasons = [];

  if (preclearance) {
    action = "ALLOW";
    reasons.push("preclearance-valid");
  } else if (effective >= 0.85) {
    action = powPassed ? "SOFT_BLOCK" : "CHALLENGE";
    reasons.push("high-risk");
  } else if (effective >= 0.60) {
    action = powPassed ? "ALLOW" : "CHALLENGE";
    reasons.push("medium-risk");
  } else {
    action = "ALLOW";
    reasons.push("low-risk");
  }

  return json({
    ok: true,
    action,
    score: effective,
    reasons,
    powRequired: action === "CHALLENGE"
  });
};
