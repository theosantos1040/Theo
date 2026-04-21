import crypto from 'node:crypto';
import { generateKeyPairSync } from 'node:crypto';
let kvClient = null;
try {
  const mod = await import('@vercel/kv');
  kvClient = mod.kv;
} catch {}

const mem = globalThis.__asoMem || (globalThis.__asoMem = new Map());

export async function kvGet(key) {
  if (kvClient) return await kvClient.get(key);
  return mem.has(key) ? mem.get(key) : null;
}
export async function kvSet(key, value, ttlSec = 0) {
  if (kvClient) {
    if (ttlSec > 0) await kvClient.set(key, value, { ex: ttlSec });
    else await kvClient.set(key, value);
    return;
  }
  mem.set(key, value);
  if (ttlSec > 0) setTimeout(() => mem.delete(key), ttlSec * 1000).unref?.();
}
export async function kvDel(key) {
  if (kvClient) return await kvClient.del(key);
  mem.delete(key);
}
export async function kvIncr(key, ttlSec = 60) {
  if (kvClient) {
    const n = await kvClient.incr(key);
    if (n === 1) await kvClient.expire(key, ttlSec);
    return Number(n);
  }
  const n = Number(mem.get(key) || 0) + 1;
  mem.set(key, n);
  setTimeout(() => { if (mem.get(key) === n) mem.delete(key); }, ttlSec * 1000).unref?.();
  return n;
}

export function reqId(req) {
  return req.headers['x-aso-request-id'] || crypto.randomUUID();
}
export function send(res, status, body, headers = {}) {
  res.statusCode = status;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('cache-control', 'no-store');
  for (const [k, v] of Object.entries(headers)) {
    res.setHeader(k, v);
  }
  res.end(JSON.stringify(body));
}
export async function readJson(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  if (!chunks.length) return {};
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return null; }
}
export function parseCookies(req) {
  const raw = req.headers.cookie || '';
  const out = {};
  for (const part of raw.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (!k) continue;
    out[k] = decodeURIComponent(rest.join('=') || '');
  }
  return out;
}
export function normalize(text, max = 120) {
  return typeof text === 'string' ? text.normalize('NFKC').trim().slice(0, max) : '';
}
export function sign(value) {
  const secret = process.env.ASO_SESSION_SECRET || 'dev-secret-change-me';
  return crypto.createHmac('sha256', secret).update(value).digest('base64url');
}
export function signToken(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${data}.${sign(data)}`;
}
export function verifyToken(token) {
  if (!token || !token.includes('.')) return null;
  const [data, sig] = token.split('.', 2);
  if (sign(data) !== sig) return null;
  try {
    const payload = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    if (Date.now() > Number(payload.exp || 0)) return null;
    return payload;
  } catch { return null; }
}
export function sessionCookies(sessionId) {
  const base = 'Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=43200';
  return [`aso_session=${encodeURIComponent(sessionId)}; ${base}`];
}
export function clearCookies() {
  return [`aso_session=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0`];
}
export async function getSession(req) {
  const sid = parseCookies(req).aso_session;
  if (!sid) return null;
  const data = await kvGet(`session:${sid}`);
  if (!data) return null;
  return { id: sid, ...data };
}
export async function setSession(id, data) {
  await kvSet(`session:${id}`, data, 43200);
}
export async function deleteSession(id) {
  await kvDel(`session:${id}`);
}
export function passwordHash(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}
export function verifyPassword(password, salt, hash) {
  const a = Buffer.from(passwordHash(password, salt), 'hex');
  const b = Buffer.from(hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
export function generateKeyRecord(label, owner, plan) {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const publicId = 'pub_' + crypto.randomBytes(18).toString('base64url');
  const secret = 'sec_' + crypto.randomBytes(32).toString('base64url');
  return {
    id: crypto.randomUUID(),
    label,
    owner,
    plan,
    publicId,
    secret,
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    createdAt: new Date().toISOString()
  };
}
export function planThresholds(plan = 'BASIC') {
  switch (String(plan).toUpperCase()) {
    case 'ENTERPRISE': return { challengeAt: 0.35, blockAt: 0.72 };
    case 'PRO': return { challengeAt: 0.5, blockAt: 0.84 };
    default: return { challengeAt: 0.74, blockAt: 0.95 };
  }
}
export function computeTelemetryRisk(telemetry = {}) {
  let score = 0;
  const ua = String(telemetry.ua || '');
  const pointer = telemetry.behavior?.pointer || [];
  const scroll = telemetry.behavior?.scroll || [];
  const fp = telemetry.fp || {};
  if (!ua) score += 0.15;
  if (/headless|webdriver|playwright|puppeteer/i.test(ua)) score += 0.6;
  if ((pointer?.length || 0) < 3) score += 0.15;
  if ((scroll?.length || 0) < 1) score += 0.05;
  if (!fp.canvas) score += 0.08;
  if (!fp.webgl) score += 0.08;
  if (!fp.audio) score += 0.08;
  return Math.max(0, Math.min(1, score));
}
export async function rateLimit(key, max, ttlSec) {
  const n = await kvIncr(key, ttlSec);
  return { ok: n <= max, count: n };
}
export async function pushErrorLog(event) {
  const key = `errors:${Date.now()}:${crypto.randomUUID()}`;
  await kvSet(key, event, 86400);
}
