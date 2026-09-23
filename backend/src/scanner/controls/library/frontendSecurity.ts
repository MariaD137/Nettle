import type { Control } from "../types";
import { registerControl } from "../registry";

export const FE_001: Control = {
  controlKey: "FE-001",
  category: "Frontend Security",
  subcategory: "Browser storage",
  name: "No sensitive data stored in localStorage/sessionStorage",
  description:
    "localStorage and sessionStorage are plain JavaScript-accessible storage — any script running on the page, " +
    "including an XSS payload, can read every value in them. Storing a token, secret, or credential there hands " +
    "an attacker who achieves XSS a working session for free, with no further exploitation needed.",
  question: "Are tokens, secrets, and credentials kept out of localStorage/sessionStorage?",
  defaultSeverity: "high",
  passCriteria: "No scanned frontend file calls localStorage/sessionStorage setItem/getItem with a key or value that names a token/secret/password/session/auth/credential/API key.",
  failCriteria: "A scanned frontend file calls localStorage/sessionStorage setItem/getItem with a key or value that names a token/secret/password/session/auth/credential/API key.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so browser storage usage was not checked in it.",
  whyItMatters:
    "An HttpOnly cookie is invisible to JavaScript entirely — an XSS payload can't read it no matter what it " +
    "runs. localStorage has no such protection by design; it exists specifically to be readable by any script on " +
    "the page. This turns an XSS bug that would otherwise be limited to defacement or phishing into full session " +
    "takeover.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Move session tokens to an HttpOnly cookie instead of localStorage/sessionStorage.",
      developerFix: "Set the session token as an HttpOnly, Secure, SameSite cookie from the server, and stop reading/writing it from client-side JavaScript entirely. If browser storage is genuinely needed for something, store only non-sensitive identifiers there, never a credential.",
      codeExample: "res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'strict' });",
    },
  ],
  longTermHardening: "Add a lint rule or CI check that flags any new localStorage/sessionStorage call referencing a sensitive-sounding key name.",
  verificationMethod: "Rescan and confirm no sensitive-sounding key is stored in localStorage/sessionStorage.",
  references: ["OWASP: HTML5 Security Cheat Sheet — Local Storage"],
  complianceMappings: [],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

export const FE_002: Control = {
  controlKey: "FE-002",
  category: "Frontend Security",
  subcategory: "Cross-site scripting",
  name: "No unescaped HTML injection",
  description:
    "dangerouslySetInnerHTML, direct .innerHTML assignment, and document.write() all insert raw HTML into the " +
    "page without escaping. If any of the content passed to them includes user input, this is a direct, " +
    "unmitigated XSS vulnerability.",
  question: "Is raw HTML insertion avoided, or sanitized when unavoidable?",
  defaultSeverity: "high",
  passCriteria: "No scanned frontend file uses dangerouslySetInnerHTML, direct .innerHTML assignment, or document.write().",
  failCriteria: "A scanned frontend file uses dangerouslySetInnerHTML, direct .innerHTML assignment, or document.write().",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so HTML-insertion patterns were not checked in it.",
  whyItMatters:
    "These three APIs exist specifically to bypass the framework's/browser's normal escaping. React JSX escapes " +
    "text content automatically; dangerouslySetInnerHTML is named the way it is because it opts back out of that " +
    "protection. Once any of these renders attacker-controlled content unescaped, that content executes as script " +
    "in the victim's browser, in the application's own origin.",
  technologyFixes: [
    {
      technology: "react",
      quickFix: "Render text content normally (JSX escapes it automatically) instead of dangerouslySetInnerHTML, or sanitize first with DOMPurify.sanitize(html).",
      developerFix: "Reserve dangerouslySetInnerHTML for content that is never user-controlled (a CMS field you trust, static markup you wrote). For anything that includes user input, sanitize with DOMPurify before rendering, or restructure to avoid raw HTML entirely.",
      codeExample: "<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />",
    },
    {
      technology: "generic",
      quickFix: "Use text content (textContent, not innerHTML) instead of raw HTML insertion. If you must render HTML, sanitize it first with DOMPurify.",
      developerFix: "Replace element.innerHTML = x with element.textContent = x wherever the content doesn't need to contain actual markup. Where it does, sanitize with a library like DOMPurify before assignment.",
    },
  ],
  longTermHardening: "Add a Content-Security-Policy that restricts script sources, so even a successful HTML injection has a harder time executing an external payload.",
  verificationMethod: "Rescan and confirm no unescaped HTML-insertion pattern remains, or that it now sanitizes its input.",
  references: ["OWASP: DOM-based XSS Prevention Cheat Sheet"],
  complianceMappings: [],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

export const FE_003: Control = {
  controlKey: "FE-003",
  category: "Frontend Security",
  subcategory: "Cross-site scripting",
  name: "No inline event handlers with embedded logic",
  description:
    "An inline event handler attribute (onclick=\"handler()\", onload=\"...\", etc.) that calls a function puts " +
    "executable script directly in HTML markup. If that markup is ever built with any user-controlled content " +
    "nearby, an attacker can close the attribute and inject their own handler.",
  question: "Are event handlers attached via addEventListener/framework bindings rather than inline HTML attributes?",
  defaultSeverity: "medium",
  passCriteria: "No scanned frontend file contains an inline on*=\"...(...)\" event handler attribute calling a function.",
  failCriteria: "A scanned frontend file contains an inline on*=\"...(...)\" event handler attribute calling a function.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so inline event handlers were not checked in it.",
  whyItMatters:
    "Inline event handlers also make a strict Content-Security-Policy (one without 'unsafe-inline') impossible to " +
    "adopt, since the browser can't distinguish a legitimate inline handler from an injected one — CSP's script " +
    "protection works by disallowing inline script entirely, and an inline handler is exactly that.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Replace the inline handler with addEventListener in JavaScript, or the framework's event-binding syntax (onClick={handler} in React).",
      developerFix: "Move all event wiring out of HTML attributes and into script — either addEventListener calls or a framework's own binding syntax, both of which a CSP can allow without permitting arbitrary inline script.",
      codeExample: "// Instead of: <button onclick=\"submit()\">\ndocument.querySelector('button').addEventListener('click', submit);",
    },
  ],
  longTermHardening: "Adopt a Content-Security-Policy without 'unsafe-inline' for script-src once inline handlers are gone — it then structurally blocks any future inline-script injection, not just the ones this scan happened to find.",
  verificationMethod: "Rescan and confirm no inline event handler with embedded logic remains.",
  references: ["OWASP: Content Security Policy Cheat Sheet"],
  complianceMappings: [],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

export const FE_004: Control = {
  controlKey: "FE-004",
  category: "Frontend Security",
  subcategory: "Information disclosure",
  name: "Source maps not exposed in production",
  description:
    "A source map reveals the original, un-minified source code — including comments, variable names, and file " +
    "structure — to anyone who opens browser devtools, making it substantially easier to find and understand a " +
    "vulnerability that minified code would otherwise obscure.",
  question: "Are source maps disabled or access-restricted in production builds?",
  defaultSeverity: "low",
  passCriteria: "No scanned file contains a sourceMappingURL comment or a build-configuration flag (sourceMap: true, devtool: 'source-map') that would ship source maps to production.",
  failCriteria: "A scanned file contains a sourceMappingURL comment or a build-configuration flag that ships source maps to production.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so source-map configuration was not checked in it.",
  whyItMatters:
    "Minification is a real, if modest, obstacle to casual code reading — a source map removes that obstacle " +
    "entirely and for free, handing an attacker the same view of the code a developer has in their own editor.",
  technologyFixes: [
    {
      technology: "generic",
      quickFix: "Disable source maps in production builds, or restrict access to them behind authentication.",
      developerFix: "Set devtool: false (webpack) or the equivalent for your bundler in the production build config. If source maps are needed for error-tracking tools, upload them directly to the tracking service instead of publishing them alongside the deployed bundle.",
      codeExample: "// webpack.prod.js\nmodule.exports = { devtool: false, /* ... */ };",
    },
  ],
  verificationMethod: "Rescan and confirm no source-map reference remains in the production build output.",
  references: [],
  complianceMappings: [],
  releaseImpactBySeverity: { critical: "BLOCK_RELEASE", high: "REVIEW_BEFORE_RELEASE", medium: "FIX_RECOMMENDED", low: "IMPROVEMENT", info: "INFORMATIONAL" },
  enabled: true,
  version: "1.0.0",
};

registerControl(FE_001);
registerControl(FE_002);
registerControl(FE_003);
registerControl(FE_004);
