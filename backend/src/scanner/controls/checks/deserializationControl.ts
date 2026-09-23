import fs from "fs";
import path from "path";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

const DESERIALIZATION_PATTERNS = [
  /JSON\.parse\s*\(\s*req\.(body|query|params)/,
  /unserialize\s*\(/,
  /deserialize\s*\([^)]*req\./,
  /node-serialize/,
  /js-yaml.*safeLoad|yaml\.load\s*\(/,
  /eval\s*\(\s*JSON/,
];

/**
 * INPUT-002, wired to the control library. Extracted from apiSecurity.ts's
 * former inline unsafe-deserialization block -- same detection logic and
 * title/detail/remediation text, restructured to emit CheckResult with a
 * controlKey and to survive an unreadable file. Per-file, like INPUT-001,
 * since each pattern match is tied to a specific line in a specific file.
 */
export function scanDeserializationControl(files: string[], targetRoot: string): CheckResult[] {
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
        checkId: generateCheckId("Security", "INPUT-002:unreadable", relFile),
        status: "NOT_VERIFIED",
        category: "Security",
        title: "File could not be read for deserialization analysis",
        detail: `${(err as Error).message}`,
        file: relFile,
        confidence: 0,
        detectionMethod: "regex",
        controlKey: "INPUT-002",
      });
      continue;
    }

    anyFileRead = true;
    for (const pat of DESERIALIZATION_PATTERNS) {
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
        checkId: generateCheckId("Security", "INPUT-002:fail", relFile),
        status: "FAIL",
        category: "Security",
        title: "Potentially unsafe deserialization",
        detail: "Deserializing untrusted data can lead to remote code execution if the deserialization library allows object construction or code execution.",
        severity: "high",
        file: relFile,
        line: lineNum,
        confidence: 70,
        detectionMethod: "regex",
        remediation: "Avoid deserializing untrusted input. Use JSON.parse only with proper schema validation afterward. Never use eval or unserialize on user input. For YAML, use yaml.safeLoad instead of yaml.load.",
        controlKey: "INPUT-002",
      });
      break; // one finding per file, matching prior behavior
    }
  }

  if (!anyFailure && anyFileRead) {
    results.push({
      checkId: generateCheckId("Security", "INPUT-002:pass"),
      status: "PASS",
      category: "Security",
      title: "No unsafe deserialization patterns detected",
      confidence: 70,
      detectionMethod: "regex",
      controlKey: "INPUT-002",
    });
  }

  return results;
}
