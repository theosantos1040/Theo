import crypto from "node:crypto";
import { json, clientIp, getSecurityStore, CONFIG } from "./_shared.mjs";

export default async (req) => {
  if (req.method !== "GET") return json({ ok: false, error: "method-not-allowed" }, 405);
  const store = await getSecurityStore();
  const ip = clientIp(req);
  const challengeId = crypto.randomUUID();
  const salt = crypto.randomBytes(16).toString("hex");
  const difficulty = CONFIG.powDifficulty;
  const expiresAt = Date.now() + 120000;

  await store.setJSON(`pow:${challengeId}`, { ip, salt, difficulty, expiresAt });

  return json({
    ok: true,
    challengeId,
    salt,
    difficulty,
    expiresAt
  });
};
