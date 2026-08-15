import path from "path";
import { walk } from "./walk";
import { scanSecrets } from "./secrets";
import { scanDependencies } from "./dependencies";
import { scanLegalPolicy } from "./legalPolicy";
import { scanAIDisclosure } from "./aiDisclosure";
import { scanAuthHeuristic } from "./authHeuristic";
import { scanWithSemgrep } from "./semgrepScanner";
import { scanOSVVulnerabilities } from "./osvVulnerabilities";
import { scanSecurityHeaders } from "./securityHeaders";
import { scanCodeQuality } from "./codeQuality";
import { scanCrypto } from "./cryptoSecurity";
import { scanDatabaseSecurity } from "./databaseSecurity";
import { scanApiSecurity } from "./apiSecurity";
import { scanFrontendSecurity } from "./frontendSecurity";
import { scanAiSecurity } from "./aiSecurity";
import { scanSessionJwt } from "./sessionJwt";
import type { ScanReport } from "./types";

const SCANNED_EXTENSIONS = [".js", ".ts", ".jsx", ".tsx", ".env", ".json"];

const SEVERITY_PENALTY: Record<string, number> = {
  critical: 16,
  high: 10,
  medium: 5,
  low: 2,
  info: 0,
};

export function runScan(targetPath: string): ScanReport {
  const targetRoot = path.resolve(targetPath);
  const files = walk(targetRoot, SCANNED_EXTENSIONS);

  const results = [
    scanSecrets(files, targetRoot),
    scanDependencies(targetRoot),
    scanLegalPolicy(targetRoot),
    scanAIDisclosure(files),
    scanAuthHeuristic(files, targetRoot),
    scanWithSemgrep(targetRoot),
    scanOSVVulnerabilities(targetRoot),
    scanSecurityHeaders(files, targetRoot),
    scanCodeQuality(files, targetRoot),
    scanCrypto(files, targetRoot),
    scanDatabaseSecurity(files, targetRoot),
    scanApiSecurity(files, targetRoot),
    scanFrontendSecurity(files, targetRoot),
    scanAiSecurity(files, targetRoot),
    scanSessionJwt(files, targetRoot),
  ];

  const findings = results.flatMap((r) => r.findings);
  const passed = results.flatMap((r) => r.passed);

  let score = 100;
  for (const f of findings) score -= SEVERITY_PENALTY[f.severity] ?? 7;
  score = Math.max(0, Math.min(100, score));

  return {
    scannedAt: new Date().toISOString(),
    target: path.basename(targetRoot),
    score,
    findings,
    passed,
    summary: {
      critical: findings.filter((f) => f.severity === "critical").length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
      info: findings.filter((f) => f.severity === "info").length,
      clear: passed.length,
    },
  };
}

export type { ScanReport, Finding, Pass, Severity } from "./types";
