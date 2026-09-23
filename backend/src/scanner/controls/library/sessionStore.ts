import type { Control } from "../types";
import { registerControl } from "../registry";

export const AUTH_006: Control = {
  controlKey: "AUTH-006",
  category: "Session Management",
  subcategory: "Session storage",
  name: "Persistent session store for express-session",
  description:
    "express-session's default MemoryStore is explicitly documented by the library itself as unsuitable for " +
    "production — it leaks memory over time, does not scale across more than one process, and every session is " +
    "lost whenever the process restarts.",
  question: "Is express-session configured with a persistent, external store?",
  defaultSeverity: "medium",

  passCriteria: "A session store option is configured pointing at an external store (Redis, MongoDB, Sequelize, Memcached).",
  failCriteria: "express-session is used with no store option configured, leaving the default in-memory MemoryStore.",
  notVerifiedCriteria: "A file matched by the scan's inclusion rules could not be read, so the session store configuration was not checked.",

  whyItMatters:
    "MemoryStore keeps every session in the Node process's own heap. It grows without bound (a real memory leak " +
    "under sustained traffic), every user is logged out on every deploy or crash, and it silently breaks the moment " +
    "the app runs more than one instance — a request landing on a different instance has no session at all.",

  technologyFixes: [
    {
      technology: "express",
      quickFix: "Configure a Redis-backed store: npm install connect-redis, then store: new RedisStore({ client: redisClient }).",
      developerFix: "Use connect-redis (Redis), connect-mongo (MongoDB), or connect-pg-simple (PostgreSQL) as the session store, matching whatever data store the app already runs.",
      architectureFix: "Prefer whichever persistent store the application already operates (its own database or a Redis cache it already runs) rather than introducing a new stateful dependency just for sessions.",
      codeExample: "const RedisStore = require('connect-redis').default;\napp.use(session({ store: new RedisStore({ client: redisClient }), secret: process.env.SESSION_SECRET }));",
    },
    {
      technology: "generic",
      quickFix: "Configure an external, persistent session store instead of relying on the framework's in-memory default.",
      developerFix: "Point the session middleware at a store backed by Redis, the application's own database, or another shared, persistent data store.",
    },
  ],

  longTermHardening: "Monitor the session store's size and set a TTL matching the session's own maxAge, so expired sessions don't accumulate indefinitely.",
  verificationMethod: "Rescan and confirm a persistent store option is now configured for express-session.",
  references: ["express-session documentation: Compatible Session Stores"],
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

registerControl(AUTH_006);
