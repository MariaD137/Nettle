import fs from "fs";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const EXPRESS_SESSION_PATTERN = /express-session|require\(\s*['"]express-session['"]\s*\)/;
const SESSION_STORE_PATTERN = /store\s*:\s*new\s+(Redis|Mongo|Sequelize|Memcached|Session)/i;

/**
 * AUTH-006, wired to the control library. Extracted from sessionJwt.ts's
 * former inline session-store block -- same detection logic and
 * title/detail/remediation text, restructured to emit CheckResult with a
 * controlKey and to survive an unreadable file. Aggregate: session
 * middleware configuration is normally defined once at the app's entry
 * point.
 */
export function scanSessionStoreControl(files: string[], targetRoot: string): CheckResult[] {
  const jsFiles = files.filter((f) => /\.(js|ts|jsx|tsx)$/.test(f));

  let allSource = "";
  let anyUnreadable = false;
  for (const file of jsFiles) {
    try {
      allSource += fs.readFileSync(file, "utf8") + "\n";
    } catch {
      anyUnreadable = true;
    }
  }

  const usesSession = EXPRESS_SESSION_PATTERN.test(allSource);
  if (!usesSession) {
    if (anyUnreadable) {
      return [
        {
          checkId: generateCheckId("Session Management", "AUTH-006:unreadable"),
          status: "NOT_VERIFIED",
          category: "Session Management",
          title: "Some files could not be read for session-store analysis",
          detail: "No express-session usage was found in the files that could be read, but at least one file was unreadable and may have used it.",
          confidence: 0,
          detectionMethod: "heuristic",
          controlKey: "AUTH-006",
        },
      ];
    }
    return []; // app doesn't use express-session at all — nothing to check
  }

  const hasSessionStore = SESSION_STORE_PATTERN.test(allSource);
  if (hasSessionStore) {
    return [
      {
        checkId: generateCheckId("Session Management", "AUTH-006:pass"),
        status: "PASS",
        category: "Session Management",
        title: "Persistent session store configured",
        confidence: 75,
        detectionMethod: "heuristic",
        controlKey: "AUTH-006",
      },
    ];
  }

  if (anyUnreadable) {
    return [
      {
        checkId: generateCheckId("Session Management", "AUTH-006:unreadable"),
        status: "NOT_VERIFIED",
        category: "Session Management",
        title: "express-session is used but not every file could be read for session-store analysis",
        detail: "No persistent store was found in the files that could be read, but at least one file was unreadable and may have configured one.",
        confidence: 0,
        detectionMethod: "heuristic",
        controlKey: "AUTH-006",
      },
    ];
  }

  return [
    {
      checkId: generateCheckId("Session Management", "AUTH-006:fail"),
      status: "FAIL",
      category: "Session Management",
      title: "Express sessions using default in-memory store",
      detail: "The default MemoryStore leaks memory, doesn't scale across processes, and loses all sessions on restart.",
      severity: "medium",
      confidence: 75,
      detectionMethod: "heuristic",
      remediation: "Use a persistent session store: new RedisStore({ client: redisClient }) or connect-mongo for MongoDB.",
      controlKey: "AUTH-006",
    },
  ];
}
