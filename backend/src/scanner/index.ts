import path from "path";
import { walk } from "./walk";
import { scanSecrets } from "./secrets";
import { scanDependencies } from "./dependencies";
import { scanLegalPolicy } from "./legalPolicy";
import { scanAIDisclosure } from "./aiDisclosure";
import { scanAuthHeuristic } from "./authHeuristic";
import { scanAuthAnalysis } from "./authAnalysisScan";
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
import { SCANNER_VERSION, type ScanReport } from "./types";
import { getSemgrepVersion } from "./initialization";
import { SCORING_CONFIG, calculateScore, calculateConfidence } from "./scoringConfig";

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
    scanAuthAnalysis(files, targetRoot),
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

  // Calculate score using versioned config (excludes NOT_VERIFIED from penalty)
  const score = calculateScore(findings, SCORING_CONFIG);

  // Calculate confidence: what percentage of checks completed?
  // For now, based on legacy model (we'll enhance when migrating to CheckResult)
  // Confidence = 100% until we migrate to checkResults with NOT_VERIFIED
  const scoreConfidence = 100;

  return {
    scannedAt: new Date().toISOString(),
    target: path.basename(targetRoot),
    scannerVersion: SCANNER_VERSION,
    semgrepVersion: getSemgrepVersion(),
    score,
    scoreConfidence,
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
