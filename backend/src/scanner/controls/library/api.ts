import type { Control } from "../types";
import { registerControl } from "../registry";

export const API_001: Control = {
  controlKey: "API-001",
  category: "API Security",
  subcategory: "Abuse protection",
  name: "Rate limiting on API endpoints",
  description:
    "Routes that accept requests must be bounded against high-volume abuse — brute-force login attempts, " +
    "credential stuffing, scraping, and simple denial of service — by a rate limiter.",
  question: "Are the application's API routes protected by rate limiting?",
  defaultSeverity: "high",

  passCriteria: "A recognized rate-limiting mechanism (middleware, decorator, or library) is present in the scanned source.",
  failCriteria: "The application defines routes but no rate-limiting pattern was found anywhere in the scanned source.",
  notVerifiedCriteria:
    "Rate limiting configured at the infrastructure layer (a reverse proxy, API gateway, or CDN) is invisible to a " +
    "source-code scan — Nettle can only confirm application-level rate limiting is absent, not that no rate limiting exists at all.",

  whyItMatters:
    "Without a bound on request volume, a single client can attempt unlimited login guesses, scrape the entire " +
    "dataset, or send enough traffic to exhaust server resources — all with a normal HTTP client, no exploit required.",

  technologyFixes: [
    {
      technology: "express",
      quickFix: "npm install express-rate-limit, then app.use(rateLimit({ windowMs: 15*60*1000, max: 100 })).",
      developerFix: "Apply express-rate-limit globally or per-route, with a tighter limit on authentication endpoints (login, signup, password reset) than on general API routes.",
      architectureFix: "For a multi-instance deployment, back the limiter with a shared store (Redis, or a database table) rather than in-memory counters, so limits are enforced consistently across instances.",
      codeExample: "const rateLimit = require('express-rate-limit');\napp.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, max: 10 }));",
    },
    {
      technology: "fastapi",
      quickFix: "pip install slowapi, then apply the Limiter as a dependency on sensitive routes.",
      developerFix: "Use slowapi (built on limits) with a per-route or per-router rate limit, tighter on authentication endpoints.",
      architectureFix: "Back the limiter with Redis for multi-instance deployments rather than the default in-memory backend.",
      codeExample: "from slowapi import Limiter\nlimiter = Limiter(key_func=get_remote_address)\n@app.post('/login')\n@limiter.limit('10/15minutes')\ndef login(): ...",
    },
    {
      technology: "django",
      quickFix: "pip install django-ratelimit, then decorate sensitive views with @ratelimit.",
      developerFix: "Use django-ratelimit (or DRF's built-in throttling classes) on authentication and other sensitive views.",
      architectureFix: "Use DRF's ScopedRateThrottle with Redis as the cache backend for consistent enforcement across instances.",
      codeExample: "from django_ratelimit.decorators import ratelimit\n@ratelimit(key='ip', rate='10/15m')\ndef login(request): ...",
    },
    {
      technology: "generic",
      quickFix: "Add a rate-limiting middleware or decorator in front of routes that accept requests, especially authentication endpoints.",
      developerFix: "Bound requests per identity (IP, account, or API key) within a time window, returning 429 once the limit is exceeded.",
      architectureFix: "Back the limiter with a shared store so limits hold across multiple server instances, not just per-process counters.",
    },
  ],

  longTermHardening: "Layer a WAF or API gateway rate limit in front of the application as defense in depth, independent of the application-level limiter.",
  verificationMethod: "Rescan and confirm a recognized rate-limiting pattern is now present in the source.",
  references: ["OWASP API Security Top 10: API4:2023 – Unrestricted Resource Consumption"],
  complianceMappings: ["SOC 2 CC6.1"],

  releaseImpactBySeverity: {
    critical: "BLOCK_RELEASE",
    high: "REVIEW_BEFORE_RELEASE",
    medium: "FIX_RECOMMENDED",
    low: "IMPROVEMENT",
    info: "INFORMATIONAL",
  },

  enabled: true,
  version: "1.0.0",
};

registerControl(API_001);
