import path from "path";
import { walk } from "./walk";
import { scanSecrets } from "./secrets";
import { scanDependencies } from "./dependencies";
import { scanLegalPolicy } from "./legalPolicy";
import { scanAIDisclosure } from "./aiDisclosure";
import { scanAuthHeuristic } from "./authHeuristic";
import type { ScanReport } from "./types";

const SCANNED_EXTENSIONS = [".js", ".ts", ".jsx", ".tsx", ".env", ".json"];

export function runScan(targetPath: string): ScanReport {
  const targetRoot = path.resolve(targetPath);
  const files = walk(targetRoot, SCANNED_EXTENSIONS);

  const results = [
    scanSecrets(files, targetRoot),
    scanDependencies(targetRoot),
    scanLegalPolicy(targetRoot),
    scanAIDisclosure(files),
    scanAuthHeuristic(files, targetRoot),
  ];

  const findings = results.flatMap((r) => r.findings);
  const passed = results.flatMap((r) => r.passed);

  let score = 100;
  for (const f of findings) score -= f.severity === "critical" ? 16 : 7;
  score = Math.max(0, Math.min(100, score));

  return {
    scannedAt: new Date().toISOString(),
    target: path.basename(targetRoot),
    score,
    findings,
    passed,
    summary: {
      critical: findings.filter((f) => f.severity === "critical").length,
      caution: findings.filter((f) => f.severity === "caution").length,
      clear: passed.length,
    },
  };
}

export type { ScanReport, Finding, Pass, Severity } from "./types";
