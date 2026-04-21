const SQLI_PATTERNS = [
  /(?:^|\b)(?:or|and)\s+['"(]?[0-9a-z_]+['")]?\s*=\s*['"(]?[0-9a-z_]+['")]?/i,
  /union\s+select/i,
  /information_schema/i,
  /sleep\s*\(/i,
  /benchmark\s*\(/i,
  /--|#|\/\*/i,
  /\b(?:drop|insert|update|delete)\b.+\b(?:table|from|into)\b/i
];

function normalize(value) {
  let current = String(value || "").normalize("NFKC");
  for (let i = 0; i < 3; i++) {
    try {
      const decoded = decodeURIComponent(current);
      if (decoded === current) break;
      current = decoded;
    } catch {
      break;
    }
  }
  try {
    const buf = Buffer.from(current, "base64");
    const roundtrip = buf.toString("base64").replace(/=+$/, "");
    if (roundtrip && roundtrip === current.replace(/=+$/, "")) {
      current = buf.toString("utf8");
    }
  } catch {}
  return current.toLowerCase();
}

export function inspectStrings(values = []) {
  const findings = [];
  for (const raw of values) {
    const value = normalize(raw);
    if (!value) continue;
    for (const pattern of SQLI_PATTERNS) {
      if (pattern.test(value)) {
        findings.push({ type: "sqli-like", value: String(raw).slice(0, 120), pattern: pattern.toString() });
      }
    }
  }
  return findings;
}
