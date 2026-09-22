import fs from "fs";
import path from "path";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const PATH_TRAVERSAL_PATTERNS = [
  /path\.join\s*\([^)]*req\.(params|query|body)/,
  /readFile(Sync)?\s*\([^)]*req\./,
  /createReadStream\s*\([^)]*req\./,
  /\.\.\/.*req\./,
  /req\.(params|query|body)\b[^)]*\bpath\b/,
];

/**
 * INPUT-001, wired to the control library. Extracted from apiSecurity.ts's
 * former inline path-traversal block -- same detection logic and
 * title/detail/remediation text, restructured to emit CheckResult with a
 * controlKey and to survive an unreadable file.
 */
export function scanPathTraversalControl(files: string[], targetRoot: string): CheckResult[] {
  const results: CheckResult[] = [];
  const jsFiles = files.filter((f) => /\.(js|ts|jsx|tsx)$/.test(f));

  let anyFailure = false;
  let anyFileRead = false;

  for (const file of jsFiles) {
    const relFile = path.relative(targetRoot, file);
    let text: string;
    try {
      text = fs.readFileSync(file, "utf8");
    } catch (err) {
      results.push({
        checkId: generateCheckId("Security", "INPUT-001:unreadable", relFile),
        status: "NOT_VERIFIED",
        category: "Security",
        title: "File could not be read for path-traversal analysis",
        detail: `${(err as Error).message}`,
        file: relFile,
        confidence: 0,
        detectionMethod: "regex",
        controlKey: "INPUT-001",
      });
      continue;
    }

    anyFileRead = true;
    for (const pat of PATH_TRAVERSAL_PATTERNS) {
      if (!pat.test(text)) continue;

      anyFailure = true;
      const lines = text.split("\n");
      let lineNum: number | null = null;
      for (let i = 0; i < lines.length; i++) {
        if (pat.test(lines[i])) {
          lineNum = i + 1;
          break;
        }
      }
      results.push({
        checkId: generateCheckId("Security", "INPUT-001:fail", relFile),
        status: "FAIL",
        category: "Security",
        title: "Potential path traversal vulnerability",
        detail: "User input is passed directly to file system operations without sanitization. An attacker could use ../ sequences to access files outside the intended directory.",
        severity: "critical",
        file: relFile,
        line: lineNum,
        confidence: 75,
        detectionMethod: "regex",
        remediation: "Sanitize file paths by resolving them and verifying they stay within the intended directory: const safe = path.resolve(baseDir, userInput); if (!safe.startsWith(baseDir)) throw new Error('Invalid path');",
        controlKey: "INPUT-001",
      });
      break; // one finding per file, matching prior behavior
    }
  }

  if (!anyFailure && anyFileRead) {
    results.push({
      checkId: generateCheckId("Security", "INPUT-001:pass"),
      status: "PASS",
      category: "Security",
      title: "No path traversal patterns detected",
      confidence: 75,
      detectionMethod: "regex",
      controlKey: "INPUT-001",
    });
  }

  return results;
}
