import fs from "fs";
import path from "path";
import type { Finding, Pass } from "./types";

const JWT_USAGE_PATTERNS = [
  /jsonwebtoken/,
  /jwt\.sign/,
  /jwt\.verify/,
  /jose/,
  /from\s+['"]jsonwebtoken['"]/,
  /require\(\s*['"]jsonwebtoken['"]\s*\)/,
];

const JWT_EXPIRY_PATTERNS = [
  /expiresIn\s*:/,
  /expiresIn\s*,/,
  /exp\s*:/,
  /maxAge\s*:/,
];

const JWT_ALGO_PATTERNS = {
  none: /algorithm\s*:\s*['"]none['"]/i,
  hs256: /algorithm\s*:\s*['"]HS256['"]/,
  weak: /algorithm\s*:\s*['"](HS384|HS512)['"]/,
  strong: /algorithm\s*:\s*['"](RS256|RS384|RS512|ES256|ES384|ES512|EdDSA)['"]/,
};

const SESSION_PATTERNS = {
  expressSession: /express-session|require\(\s*['"]express-session['"]\s*\)/,
  sessionSecret: /secret\s*:\s*['"][^'"]+['"]/,
  sessionStore: /store\s*:\s*new\s+(Redis|Mongo|Sequelize|Memcached|Session)/i,
  sessionMaxAge: /maxAge\s*:/,
  resave: /resave\s*:\s*false/,
  saveUninitialized: /saveUninitialized\s*:\s*false/,
};

const REFRESH_TOKEN_PATTERNS = [
  /refresh[_-]?token/i,
  /refreshToken/,
  /token.*rotation/i,
  /rotate.*token/i,
];

const LOGOUT_INVALIDATION_PATTERNS = [
  /blacklist|blocklist|revoke|invalidate.*token|token.*invalid/i,
  /destroy.*session|session.*destroy|req\.session\.destroy/i,
  /delete.*token|remove.*token|clear.*session/i,
];

export function scanSessionJwt(files: string[], targetRoot: string): { findings: Finding[]; passed: Pass[] } {
  const findings: Finding[] = [];
  const passed: Pass[] = [];

  const jsFiles = files.filter((f) => /\.(js|ts|jsx|tsx)$/.test(f));
  let usesJwt = false;
  let hasExpiry = false;
  let hasAlgoNone = false;
  let hasStrongAlgo = false;
  let usesSession = false;
  let hasSessionStore = false;
  let hasSessionMaxAge = false;
  let hasRefreshToken = false;
  let hasLogoutInvalidation = false;

  for (const file of jsFiles) {
    const text = fs.readFileSync(file, "utf8");
    const rel = path.relative(targetRoot, file);

    if (JWT_USAGE_PATTERNS.some((p) => p.test(text))) usesJwt = true;
    if (JWT_EXPIRY_PATTERNS.some((p) => p.test(text))) hasExpiry = true;
    if (JWT_ALGO_PATTERNS.none.test(text)) {
      hasAlgoNone = true;
      findings.push({
        severity: "critical",
        category: "Session Management",
        title: "JWT algorithm set to 'none'",
        detail: "Using algorithm: 'none' disables signature verification entirely. Anyone can forge valid tokens.",
        file: rel,
        line: null,
        remediation: "Use a strong signing algorithm like RS256 or ES256. Never allow 'none' as an algorithm.",
      });
    }
    if (JWT_ALGO_PATTERNS.strong.test(text)) hasStrongAlgo = true;

    if (SESSION_PATTERNS.expressSession.test(text)) usesSession = true;
    if (SESSION_PATTERNS.sessionStore.test(text)) hasSessionStore = true;
    if (SESSION_PATTERNS.sessionMaxAge.test(text)) hasSessionMaxAge = true;
    if (REFRESH_TOKEN_PATTERNS.some((p) => p.test(text))) hasRefreshToken = true;
    if (LOGOUT_INVALIDATION_PATTERNS.some((p) => p.test(text))) hasLogoutInvalidation = true;
  }

  if (!usesJwt && !usesSession) return { findings, passed };

  if (usesJwt) {
    if (!hasExpiry) {
      findings.push({
        severity: "high",
        category: "Session Management",
        title: "JWT tokens issued without expiration",
        detail: "Tokens without an expiry never become invalid. A leaked token grants permanent access until the signing key is rotated.",
        file: null,
        line: null,
        remediation: "Set a short expiration on JWTs: jwt.sign(payload, secret, { expiresIn: '15m' }). Use refresh tokens for longer sessions.",
      });
    } else {
      passed.push({ category: "Session Management", title: "JWT tokens have expiration configured" });
    }

    if (hasStrongAlgo) {
      passed.push({ category: "Session Management", title: "JWT uses asymmetric signing algorithm (RS256/ES256)" });
    }

    if (!hasRefreshToken) {
      findings.push({
        severity: "medium",
        category: "Session Management",
        title: "No refresh token rotation detected",
        detail: "Without refresh tokens, either access tokens are long-lived (risky) or users must re-authenticate frequently (poor UX).",
        file: null,
        line: null,
        remediation: "Implement refresh token rotation: short-lived access tokens (15m) with one-time-use refresh tokens that rotate on each use.",
      });
    } else {
      passed.push({ category: "Session Management", title: "Refresh token pattern detected" });
    }
  }

  if (usesSession) {
    if (!hasSessionStore) {
      findings.push({
        severity: "medium",
        category: "Session Management",
        title: "Express sessions using default in-memory store",
        detail: "The default MemoryStore leaks memory, doesn't scale across processes, and loses all sessions on restart.",
        file: null,
        line: null,
        remediation: "Use a persistent session store: new RedisStore({ client: redisClient }) or connect-mongo for MongoDB.",
      });
    } else {
      passed.push({ category: "Session Management", title: "Persistent session store configured" });
    }

    if (!hasSessionMaxAge) {
      findings.push({
        severity: "medium",
        category: "Session Management",
        title: "No session expiration (maxAge) configured",
        detail: "Sessions without maxAge persist indefinitely, increasing the window for session hijacking.",
        file: null,
        line: null,
        remediation: "Set a session maxAge: cookie: { maxAge: 24 * 60 * 60 * 1000 } for a 24-hour session.",
      });
    }
  }

  if ((usesJwt || usesSession) && !hasLogoutInvalidation) {
    findings.push({
      severity: "medium",
      category: "Session Management",
      title: "No token/session invalidation on logout",
      detail: "Without explicit token blacklisting or session destruction on logout, tokens remain valid until they expire naturally.",
      file: null,
        line: null,
      remediation: "Destroy sessions on logout (req.session.destroy()) or maintain a token blacklist/revocation list for JWTs.",
    });
  } else if (hasLogoutInvalidation) {
    passed.push({ category: "Session Management", title: "Token/session invalidation on logout detected" });
  }

  return { findings, passed };
}
