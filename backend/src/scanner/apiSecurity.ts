import fs from "fs";
import path from "path";
import type { Finding, Pass } from "./types";

const RATE_LIMIT_PATTERNS = [
  /rate[_-]?limit/i,
  /express-rate-limit/,
  /rateLimit/,
  /throttle/i,
  /req.*per.*second/i,
  /too many requests/i,
];

const CORS_PATTERNS = {
  any: /cors/i,
  wildcard: /origin\s*:\s*['"]?\*['"]?|credentials\s*:\s*true.*origin\s*:\s*true/i,
  configured: /origin\s*:\s*['"\[]/,
};

const CSRF_PATTERNS = [
  /csrf/i,
  /csurf/,
  /csrfToken/,
  /xsrf/i,
  /_csrf/,
];

const PAGINATION_PATTERNS = [
  /limit\s*[:=]/i,
  /pageSize/i,
  /per_?page/i,
  /\.take\s*\(/,
  /LIMIT\s+\?/i,
  /\.limit\s*\(/,
];

const REQUEST_SIZE_PATTERNS = [
  /express\.json\s*\(\s*\{[^}]*limit/,
  /bodyParser.*limit/,
  /express\.urlencoded\s*\(\s*\{[^}]*limit/,
  /payload.*limit/i,
];

const HTTPS_PATTERNS = [
  /http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)/g,
  /https?\s*[:=]\s*false/gi,
  /rejectUnauthorized\s*:\s*false/g,
];

const FILE_UPLOAD_PATTERNS = {
  any: /multer|formidable|busboy|multipart|upload/i,
  sizeLimit: /fileSize|maxFileSize|fileSizeLimit|limits\s*:\s*\{[^}]*fileSize/i,
  typeCheck: /mimetype|mimeType|content-type.*check|fileFilter|allowedTypes|acceptedTypes/i,
};

const INPUT_VALIDATION_PATTERNS = [
  /require\(\s*['"]joi['"]\s*\)/,
  /from\s+['"]joi['"]/,
  /require\(\s*['"]zod['"]\s*\)/,
  /from\s+['"]zod['"]/,
  /require\(\s*['"]yup['"]\s*\)/,
  /from\s+['"]yup['"]/,
  /require\(\s*['"]express-validator['"]\s*\)/,
  /from\s+['"]express-validator['"]/,
  /require\(\s*['"]ajv['"]\s*\)/,
  /from\s+['"]ajv['"]/,
  /require\(\s*['"]superstruct['"]\s*\)/,
  /from\s+['"]superstruct['"]/,
  /\.safeParse\s*\(/,
  /\.validate\s*\(/,
  /\.parse\s*\(/,
];

const COOKIE_SECURITY_PATTERNS = {
  setCookie: /res\.cookie\s*\(|set-cookie|setCookie/i,
  httpOnly: /httpOnly\s*:\s*true/,
  secure: /secure\s*:\s*true/,
  sameSite: /sameSite\s*:\s*['"](strict|lax)['"]/i,
};

export function scanApiSecurity(files: string[], targetRoot: string): { findings: Finding[]; passed: Pass[] } {
  const findings: Finding[] = [];
  const passed: Pass[] = [];

  const jsFiles = files.filter((f) => /\.(js|ts|jsx|tsx)$/.test(f));
  const allSource = jsFiles.map((f) => fs.readFileSync(f, "utf8")).join("\n");

  const hasRateLimit = RATE_LIMIT_PATTERNS.some((p) => p.test(allSource));
  if (hasRateLimit) {
    passed.push({ category: "API Security", title: "Rate limiting is configured" });
  } else {
    const hasRoutes = /app\.(get|post|put|delete|patch)\s*\(/.test(allSource);
    if (hasRoutes) {
      findings.push({
        severity: "high",
        category: "API Security",
        title: "No rate limiting detected",
        detail: "Without rate limiting, the API is vulnerable to brute-force attacks, credential stuffing, denial of service, and resource exhaustion.",
        file: null,
        line: null,
        remediation: "Add rate limiting middleware: npm install express-rate-limit, then app.use(rateLimit({ windowMs: 15*60*1000, max: 100 })).",
      });
    }
  }

  if (CORS_PATTERNS.any.test(allSource)) {
    if (CORS_PATTERNS.wildcard.test(allSource)) {
      findings.push({
        severity: "high",
        category: "API Security",
        title: "CORS allows all origins (wildcard)",
        detail: "A wildcard CORS policy allows any website to make cross-origin requests to this API. Combined with credentials, this enables cross-site request attacks.",
        file: null,
        line: null,
        remediation: "Restrict CORS to your actual frontend domain: cors({ origin: 'https://yourapp.com', credentials: true }).",
      });
    } else {
      passed.push({ category: "API Security", title: "CORS is configured with specific origins" });
    }
  }

  const usesCookies = COOKIE_SECURITY_PATTERNS.setCookie.test(allSource);
  if (usesCookies) {
    const hasHttpOnly = COOKIE_SECURITY_PATTERNS.httpOnly.test(allSource);
    const hasSecure = COOKIE_SECURITY_PATTERNS.secure.test(allSource);
    const hasSameSite = COOKIE_SECURITY_PATTERNS.sameSite.test(allSource);

    if (!hasHttpOnly) {
      findings.push({
        severity: "high",
        category: "Session Management",
        title: "Cookies set without HttpOnly flag",
        detail: "Without HttpOnly, cookies are accessible to JavaScript — an XSS vulnerability can steal session tokens.",
        file: null,
        line: null,
        remediation: "Set httpOnly: true on all authentication cookies: res.cookie('session', token, { httpOnly: true }).",
      });
    }
    if (!hasSecure) {
      findings.push({
        severity: "medium",
        category: "Session Management",
        title: "Cookies set without Secure flag",
        detail: "Without the Secure flag, cookies are sent over plain HTTP, allowing interception on untrusted networks.",
        file: null,
        line: null,
        remediation: "Set secure: true on cookies in production: res.cookie('session', token, { secure: true }).",
      });
    }
    if (!hasSameSite) {
      findings.push({
        severity: "medium",
        category: "Session Management",
        title: "Cookies set without SameSite attribute",
        detail: "Without SameSite, cookies are sent with cross-site requests, enabling CSRF attacks.",
        file: null,
        line: null,
        remediation: "Set sameSite: 'strict' (or 'lax') on cookies: res.cookie('session', token, { sameSite: 'strict' }).",
      });
    }
    if (hasHttpOnly && hasSecure && hasSameSite) {
      passed.push({ category: "Session Management", title: "Cookies are configured with HttpOnly, Secure, and SameSite flags" });
    }

    const hasCsrf = CSRF_PATTERNS.some((p) => p.test(allSource));
    if (!hasCsrf) {
      findings.push({
        severity: "medium",
        category: "API Security",
        title: "No CSRF protection detected for cookie-based auth",
        detail: "The app uses cookies but no CSRF token or double-submit pattern was detected. This allows cross-site request forgery attacks.",
        file: null,
        line: null,
        remediation: "Add CSRF protection: use the SameSite cookie attribute (strict or lax), or implement CSRF tokens with a library like csrf or csurf.",
      });
    } else {
      passed.push({ category: "API Security", title: "CSRF protection is configured" });
    }
  }

  const hasInputValidation = INPUT_VALIDATION_PATTERNS.some((p) => p.test(allSource));
  if (hasInputValidation) {
    passed.push({ category: "API Security", title: "Input validation library detected (Zod, Joi, express-validator, or similar)" });
  } else {
    const hasRoutes = /app\.(post|put|patch)\s*\(/.test(allSource);
    if (hasRoutes) {
      findings.push({
        severity: "medium",
        category: "API Security",
        title: "No schema validation library detected",
        detail: "Without a validation library, request bodies are accepted as-is. Missing validation leads to type confusion, injection, and unexpected behavior.",
        file: null,
        line: null,
        remediation: "Add schema validation with Zod (npm install zod) or Joi. Validate every request body: const schema = z.object({ email: z.string().email() }); schema.parse(req.body).",
      });
    }
  }

  const hasRequestSizeLimit = REQUEST_SIZE_PATTERNS.some((p) => p.test(allSource));
  if (!hasRequestSizeLimit) {
    const usesBodyParser = /express\.json\s*\(|bodyParser/.test(allSource);
    if (usesBodyParser) {
      findings.push({
        severity: "medium",
        category: "API Security",
        title: "No request body size limit configured",
        detail: "Without a body size limit, attackers can send extremely large payloads to exhaust memory and crash the server.",
        file: null,
        line: null,
        remediation: "Set a body size limit: app.use(express.json({ limit: '1mb' })). Adjust the limit to match your largest expected payload.",
      });
    }
  } else {
    passed.push({ category: "API Security", title: "Request body size limit is configured" });
  }

  if (FILE_UPLOAD_PATTERNS.any.test(allSource)) {
    const hasSizeLimit = FILE_UPLOAD_PATTERNS.sizeLimit.test(allSource);
    const hasTypeCheck = FILE_UPLOAD_PATTERNS.typeCheck.test(allSource);
    if (!hasSizeLimit) {
      findings.push({
        severity: "high",
        category: "API Security",
        title: "File uploads without size limit",
        detail: "Without a file size limit, attackers can upload extremely large files to exhaust disk space or memory.",
        file: null,
        line: null,
        remediation: "Configure a file size limit in your upload middleware: multer({ limits: { fileSize: 5 * 1024 * 1024 } }) for a 5MB limit.",
      });
    }
    if (!hasTypeCheck) {
      findings.push({
        severity: "high",
        category: "API Security",
        title: "File uploads without MIME type or extension validation",
        detail: "Without type checking, users can upload executable files (.exe, .sh, .php) that may be served or executed by the server.",
        file: null,
        line: null,
        remediation: "Add a file filter that checks MIME types and extensions: multer({ fileFilter: (req, file, cb) => { if (!allowedTypes.includes(file.mimetype)) return cb(new Error('Invalid type')); cb(null, true); } }).",
      });
    }
    if (hasSizeLimit && hasTypeCheck) {
      passed.push({ category: "API Security", title: "File uploads have size limits and type validation" });
    }
  }

  // Path traversal detection
  const pathTraversalPatterns = [
    /path\.join\s*\([^)]*req\.(params|query|body)/,
    /readFile(Sync)?\s*\([^)]*req\./,
    /createReadStream\s*\([^)]*req\./,
    /\.\.\/.*req\./,
    /req\.(params|query|body)\b[^)]*\bpath\b/,
  ];
  let pathTraversalFound = false;
  for (const file of jsFiles) {
    const text = fs.readFileSync(file, "utf8");
    const rel = path.relative(targetRoot, file);
    for (const pat of pathTraversalPatterns) {
      if (pat.test(text)) {
        pathTraversalFound = true;
        const lines = text.split("\n");
        let lineNum: number | null = null;
        for (let i = 0; i < lines.length; i++) {
          if (pat.test(lines[i])) { lineNum = i + 1; break; }
        }
        findings.push({
          severity: "critical",
          category: "Security",
          title: "Potential path traversal vulnerability",
          detail: "User input is passed directly to file system operations without sanitization. An attacker could use ../ sequences to access files outside the intended directory.",
          file: rel,
          line: lineNum,
          remediation: "Sanitize file paths by resolving them and verifying they stay within the intended directory: const safe = path.resolve(baseDir, userInput); if (!safe.startsWith(baseDir)) throw new Error('Invalid path');",
        });
        break;
      }
    }
  }
  if (!pathTraversalFound) {
    passed.push({ category: "Security", title: "No path traversal patterns detected" });
  }

  // Unsafe deserialization detection.
  //
  // Deliberately does NOT include plain JSON.parse(req.body) — unlike the
  // patterns below, JSON.parse can't execute code or construct arbitrary
  // objects/classes from its input, so it isn't "unsafe deserialization" in
  // the RCE/object-injection sense this finding warns about. Flagging it
  // the same as node-serialize or an unguarded eval would put a completely
  // ordinary, safe Express pattern behind the same "can lead to remote code
  // execution" wording as things that genuinely can.
  const deserializationPatterns = [
    /unserialize\s*\(/,
    /deserialize\s*\([^)]*req\./,
    /node-serialize/,
    /js-yaml.*safeLoad|yaml\.load\s*\(/,
    /eval\s*\(\s*JSON/,
  ];
  let deserializationFound = false;
  for (const file of jsFiles) {
    const text = fs.readFileSync(file, "utf8");
    const rel = path.relative(targetRoot, file);
    for (const pat of deserializationPatterns) {
      if (pat.test(text)) {
        deserializationFound = true;
        findings.push({
          severity: "high",
          category: "Security",
          title: "Potentially unsafe deserialization",
          detail: "Deserializing untrusted data can lead to remote code execution if the deserialization library allows object construction or code execution.",
          file: rel,
          line: null,
          remediation: "Avoid deserializing untrusted input with libraries that can construct arbitrary objects or execute code (node-serialize, unserialize, eval, yaml.load). For YAML, use yaml.safeLoad instead of yaml.load. Plain JSON.parse is safe from this class of issue, but still validate the resulting data against a schema before trusting it.",
        });
        break;
      }
    }
  }
  if (!deserializationFound) {
    passed.push({ category: "Security", title: "No unsafe deserialization patterns detected" });
  }

  for (const file of jsFiles) {
    const text = fs.readFileSync(file, "utf8");
    const rel = path.relative(targetRoot, file);
    for (const pattern of HTTPS_PATTERNS) {
      const matches = text.match(pattern);
      if (matches && matches.length > 0) {
        const isRejectUnauthorized = /rejectUnauthorized/.test(matches[0]);
        findings.push({
          severity: isRejectUnauthorized ? "critical" : "medium",
          category: "Security",
          title: isRejectUnauthorized ? "TLS certificate verification disabled" : "Non-HTTPS URL in server code",
          detail: isRejectUnauthorized
            ? "Disabling certificate verification makes the connection vulnerable to man-in-the-middle attacks."
            : `Found ${matches.length} non-localhost HTTP URL(s). Data sent over HTTP is visible to anyone on the network path.`,
          file: rel,
        line: null,
          remediation: isRejectUnauthorized
            ? "Remove rejectUnauthorized: false. If you need to trust a custom CA, configure the CA certificate explicitly."
            : "Change HTTP URLs to HTTPS. If connecting to a local service, use localhost or 127.0.0.1.",
        });
        break;
      }
    }
  }

  return { findings, passed };
}
