import crypto from "node:crypto";
const password = process.argv[2];
if (!password) {
  console.error("Use: node scripts/hash-password.mjs <password>");
  process.exit(1);
}
const salt = crypto.randomBytes(16).toString("hex");
const hash = crypto.scryptSync(password, salt, 64).toString("hex");
console.log("ASO_ADMIN_PASSWORD_SALT=" + salt);
console.log("ASO_ADMIN_PASSWORD_HASH=" + hash);
