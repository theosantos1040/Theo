import crypto from "node:crypto";
import { getStore } from "@netlify/blobs";

export const CONFIG = {
  adminUser: process.env.ASO_ADMIN_USER || "admin",
  adminPasswordHash: process.env.ASO_ADMIN_PASSWORD_HASH || "",
  adminPasswordSalt: process.env.ASO_ADMIN_PASSWORD_SALT || "",
  sessionSecret: process.env.ASO_SESSION_SECRET || "dev-session-secret-change-me",
  csrfSecret: process.env.ASO_CSRF_SECRET || "dev-csrf-secret-change-me",
  loginWindowMs: 10 * 60 * 1000,
  loginAttemptsPerWindow: 5,
  lockoutMs: 15 * 60 * 1000,
  powSecret: process.env.ASO_POW_SECRET || "dev-pow-secret-change-me",
  powDifficulty: Number(process.env.ASO_POW_DIFFICULTY || 4),
  siemDatadogApiKey: process.env.ASO_DATADOG_API_KEY || "",
  siemDatadogSite: process.env.ASO_DATADOG_SITE || "datadoghq.com",
  siemSplunkHecUrl: process.env.ASO_SPLUNK_HEC_URL || "",
  siemSplunkHecToken: process.env.ASO_SPLUNK_HEC_TOKEN || ""
};


export function json(body, status = 200, extraHeaders = {}) {
  const headers = new Headers({
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer"
  });

  for (const [key, value] of Object.entries(extraHeaders || {})) {
    if (Array.isArray(value)) {
      for (const item of value) headers.append(key, String(item));
    } else if (value !== undefined && value !== null) {
      headers.set(key, String(value));
    }
  }

  return new Response(JSON.stringify(body), { status, headers });
}

export function parseCookies(req) {
  const out = {};
  const raw = req.headers.get("cookie") || "";
  for (const part of raw.split(";")) {
    const idx = part.indexOf("=");
    if (idx === -1) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1));
  }
  return out;
}

export function sign(value, secret) {
  return crypto.createHmac("sha256", secret).update(value).digest("base64url");
}

export function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function timingSafeHexCompare(aHex, bHex) {
  const a = Buffer.from(aHex, "hex");
  const b = Buffer.from(bHex, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export function verifyPassword(password) {
  if (!CONFIG.adminPasswordHash || !CONFIG.adminPasswordSalt) return false;
  const calculated = crypto.scryptSync(password, CONFIG.adminPasswordSalt, 64).toString("hex");
  return timingSafeHexCompare(calculated, CONFIG.adminPasswordHash);
}

export function normalizeIdentifier(value, max = 80) {
  if (typeof value !== "string") return "";
  return value.normalize("NFKC").trim().slice(0, max);
}

export async function strictJson(req) {
  try {
    const body = await req.json();
    if (!body || typeof body !== "object" || Array.isArray(body)) return null;
    return body;
  } catch {
    return null;
  }
}

export function clientIp(req) {
  const xff = req.headers.get("x-forwarded-for");
  return xff ? xff.split(",")[0].trim() : "0.0.0.0";
}

export async function getSecurityStore() {
  return getStore("aso-shield-admin");
}

export async function getSession(req) {
  const cookies = parseCookies(req);
  const sid = cookies.aso_sid;
  const sig = cookies.aso_sig;
  if (!sid || !sig) return null;
  if (sig !== sign(sid, CONFIG.sessionSecret)) return null;
  const store = await getSecurityStore();
  const session = await store.getJSON(`session:${sid}`);
  if (!session) return null;
  if (Date.now() > session.expiresAt) return null;
  return { id: sid, ...session };
}

export function issueSessionHeaders(id) {
  const common = "Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=43200";
  const sid = `aso_sid=${encodeURIComponent(id)}; ${common}`;
  const sig = `aso_sig=${encodeURIComponent(sign(id, CONFIG.sessionSecret))}; ${common}`;
  return [sid, sig];
}

export function clearSessionHeaders() {
  const common = "Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0";
  return [`aso_sid=; ${common}`, `aso_sig=; ${common}`];
}

export async function checkThrottle(ip) {
  const store = await getSecurityStore();
  const key = `throttle:${ip}`;
  const state = (await store.getJSON(key)) || { attempts: [], lockedUntil: 0 };
  const now = Date.now();
  state.attempts = state.attempts.filter((ts) => now - ts < CONFIG.loginWindowMs);
  if (state.lockedUntil > now) return { ok: false, retryAfterMs: state.lockedUntil - now };
  await store.setJSON(key, state);
  return { ok: true };
}

export async function failLogin(ip) {
  const store = await getSecurityStore();
  const key = `throttle:${ip}`;
  const now = Date.now();
  const state = (await store.getJSON(key)) || { attempts: [], lockedUntil: 0 };
  state.attempts = state.attempts.filter((ts) => now - ts < CONFIG.loginWindowMs);
  state.attempts.push(now);
  if (state.attempts.length >= CONFIG.loginAttemptsPerWindow) {
    state.attempts = [];
    state.lockedUntil = now + CONFIG.lockoutMs;
  }
  await store.setJSON(key, state);
}

export async function successLogin(ip) {
  const store = await getSecurityStore();
  await store.delete(`throttle:${ip}`);
}

export async function writeSession(id, session) {
  const store = await getSecurityStore();
  await store.setJSON(`session:${id}`, session);
}

export async function deleteSession(id) {
  const store = await getSecurityStore();
  await store.delete(`session:${id}`);
}

export async function listKeys() {
  const store = await getSecurityStore();
  return (await store.getJSON("keys")) || [];
}

export async function saveKeys(items) {
  const store = await getSecurityStore();
  await store.setJSON("keys", items);
}

export function generateKeyRecord(label, createdBy) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    id: crypto.randomUUID(),
    label,
    createdBy,
    createdAt: new Date().toISOString(),
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }),
    publicId: "pub_" + crypto.randomBytes(12).toString("hex"),
    secret: "sec_" + crypto.randomBytes(24).toString("base64url")
  };
}

export function summarizeMotion(points = []) {
  let energy = 0;
  let rotations = 0;
  for (const point of points) {
    energy += Math.abs(Number(point.ax || 0)) + Math.abs(Number(point.ay || 0)) + Math.abs(Number(point.az || 0));
    rotations += Math.abs(Number(point.rx || 0)) + Math.abs(Number(point.ry || 0)) + Math.abs(Number(point.rz || 0));
  }
  return { energy, rotations };
}

export function summarizePointer(points = []) {
  if (!Array.isArray(points) || points.length < 2) return { path: 0, meanDt: 0, varianceDt: 0 };
  const dts = [];
  let path = 0;
  for (let i = 1; i < points.length; i++) {
    const dx = Number(points[i].x || 0) - Number(points[i - 1].x || 0);
    const dy = Number(points[i].y || 0) - Number(points[i - 1].y || 0);
    const dt = Math.max(0, Number(points[i].t || 0) - Number(points[i - 1].t || 0));
    path += Math.sqrt(dx * dx + dy * dy);
    dts.push(dt);
  }
  const meanDt = dts.reduce((a, b) => a + b, 0) / dts.length;
  const varianceDt = dts.reduce((a, b) => a + Math.pow(b - meanDt, 2), 0) / dts.length;
  return { path, meanDt, varianceDt };
}

export function computeTelemetryRisk(payload) {
  const pointer = summarizePointer(payload?.behavior?.pointer || []);
  const motion = summarizeMotion(payload?.behavior?.motion || []);
  const webdriverRisk = payload?.webdriver ? 0.45 : 0;
  const lowVarianceRisk = pointer.varianceDt < 4 && pointer.path > 200 ? 0.22 : 0;
  const emptyTelemetryRisk = (payload?.behavior?.pointer || []).length < 3 ? 0.18 : 0;
  const weakFpRisk = (!payload?.fp?.canvasHash || !payload?.fp?.webglHash) ? 0.12 : 0;
  const automationHintRisk = /Headless|PhantomJS|Electron/i.test(String(payload?.ua || "")) ? 0.35 : 0;
  const motionBonus = motion.energy > 0 ? -0.05 : 0;
  const score = Math.max(0, Math.min(1, webdriverRisk + lowVarianceRisk + emptyTelemetryRisk + weakFpRisk + automationHintRisk + motionBonus));
  return {
    score,
    factors: {
      webdriverRisk,
      lowVarianceRisk,
      emptyTelemetryRisk,
      weakFpRisk,
      automationHintRisk,
      motionBonus
    }
  };
}

export async function maybeSendToSiem(event) {
  const jobs = [];
  if (CONFIG.siemSplunkHecUrl && CONFIG.siemSplunkHecToken) {
    jobs.push(fetch(CONFIG.siemSplunkHecUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "authorization": `Splunk ${CONFIG.siemSplunkHecToken}`
      },
      body: JSON.stringify({ event, source: "aso-shield", sourcetype: "aso:security" })
    }).catch(() => null));
  }
  if (CONFIG.siemDatadogApiKey) {
    const url = `https://http-intake.logs.${CONFIG.siemDatadogSite}/api/v2/logs`;
    jobs.push(fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "DD-API-KEY": CONFIG.siemDatadogApiKey
      },
      body: JSON.stringify([event])
    }).catch(() => null));
  }
  await Promise.allSettled(jobs);
}


export async function getReputation(ip, fpKey) {
  const store = await getSecurityStore();
  const ipRep = (await store.getJSON(`reputation:ip:${ip}`)) || { score: 0, hits: 0 };
  const fpRep = fpKey ? ((await store.getJSON(`reputation:fp:${fpKey}`)) || { score: 0, hits: 0 }) : { score: 0, hits: 0 };
  return { ip: ipRep, fp: fpRep };
}

export async function updateReputation(ip, fpKey, deltaScore) {
  const store = await getSecurityStore();
  const now = Date.now();
  const updateOne = async (key) => {
    const current = (await store.getJSON(key)) || { score: 0, hits: 0, updatedAt: now };
    current.score = Math.max(-1, Math.min(1, Number(current.score || 0) + Number(deltaScore || 0)));
    current.hits = Number(current.hits || 0) + 1;
    current.updatedAt = now;
    await store.setJSON(key, current);
    return current;
  };
  const ipRep = await updateOne(`reputation:ip:${ip}`);
  const fpRep = fpKey ? await updateOne(`reputation:fp:${fpKey}`) : null;
  return { ip: ipRep, fp: fpRep };
}

export function makePreclearanceToken(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = sign(data, CONFIG.sessionSecret);
  return `${data}.${sig}`;
}

export function verifyPreclearanceToken(token) {
  if (!token || typeof token !== "string" || !token.includes(".")) return null;
  const [data, sig] = token.split(".", 2);
  if (sign(data, CONFIG.sessionSecret) !== sig) return null;
  try {
    const payload = JSON.parse(Buffer.from(data, "base64url").toString("utf8"));
    if (!payload || typeof payload !== "object") return null;
    if (Date.now() > Number(payload.exp || 0)) return null;
    return payload;
  } catch {
    return null;
  }
}


export function serviceTokenSign(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = sign(data, CONFIG.sessionSecret);
  return `${data}.${sig}`;
}

export function serviceTokenVerify(token) {
  if (!token || typeof token !== "string" || !token.includes(".")) return null;
  const [data, sig] = token.split(".", 2);
  if (sign(data, CONFIG.sessionSecret) !== sig) return null;
  try {
    const payload = JSON.parse(Buffer.from(data, "base64url").toString("utf8"));
    if (!payload || typeof payload !== "object") return null;
    if (Date.now() > Number(payload.exp || 0)) return null;
    return payload;
  } catch {
    return null;
  }
}

export function planThresholds(plan = "BASIC") {
  switch (String(plan).toUpperCase()) {
    case "ENTERPRISE":
      return { challengeAt: 0.35, blockAt: 0.72, label: "ASOShieldEnterprise" };
    case "PRO":
      return { challengeAt: 0.48, blockAt: 0.82, label: "ASOShieldPro" };
    default:
      return { challengeAt: 0.72, blockAt: 0.94, label: "ASOBasic" };
  }
}
