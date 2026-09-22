import path from "path";
import { walk } from "./walk";
import { scanSecretsControl } from "./secrets";
import { scanDependencies } from "./dependencies";
import { scanLegalPolicy } from "./legalPolicy";
import { scanAIDisclosure } from "./aiDisclosure";
import { scanWithSemgrep } from "./semgrepScanner";
import { scanOSVVulnerabilities } from "./osvVulnerabilities";
import { scanCodeQuality } from "./codeQuality";
import { scanDatabaseSecurity } from "./databaseSecurity";
import { scanApiSecurity } from "./apiSecurity";
import { scanFrontendSecurity } from "./frontendSecurity";
import { scanAiSecurity } from "./aiSecurity";
import { scanSessionJwt } from "./sessionJwt";
import { scanAuthControl } from "./controls/checks/authControl";
import { scanApiRateLimitControl } from "./controls/checks/rateLimitControl";
import { scanSqlInjectionControl } from "./controls/checks/sqlInjectionControl";
import { scanSecurityHeadersControl } from "./controls/checks/securityHeadersControl";
import { scanJwtAlgorithmControl } from "./controls/checks/jwtAlgorithmControl";
import { scanCryptoControl } from "./controls/checks/cryptoControl";
import { scanAiPromptInjectionControl } from "./controls/checks/aiPromptInjectionControl";
import { scanPathTraversalControl } from "./controls/checks/pathTraversalControl";
import { scanTransportSecurityControl } from "./controls/checks/transportSecurityControl";
import { scanJwtExpiryControl } from "./controls/checks/jwtExpiryControl";
import { scanCorsControl } from "./controls/checks/corsControl";
import { detectFrameworks } from "./frameworkDetection";
import { mapFrameworkToTechnology } from "./controls/technologyMap";
import "./controls"; // registers the control library (AUTH-001, AUTH-002, AUTH-003, SECRET-001, API-001, API-002, DB-001, BROWSER-001, CRYPTO-001, AI-001, INPUT-001, NET-001, ...)
import { getControlLibraryVersion, getControlVersionsSnapshot } from "./controls";
import { SCANNER_VERSION, type CheckResult, type Finding, type Pass, type ScanReport } from "./types";
import { getSemgrepVersion } from "./initialization";
import { SCORING_CONFIG, calculateScore, calculateConfidence } from "./scoringConfig";
import { checkResultToFinding, checkResultToPass, findingToCheckResult, passToCheckResult } from "./threeStateModel";

const SCANNED_EXTENSIONS = [".js", ".ts", ".jsx", ".tsx", ".env", ".json"];

export function runScan(targetPath: string): ScanReport {
  const targetRoot = path.resolve(targetPath);
  const files = walk(targetRoot, SCANNED_EXTENSIONS);

  // Checks migrated onto the control library (see scanner/controls/) produce
  // CheckResult directly, including NOT_VERIFIED where the old
  // Finding/Pass-only modules could only silently contribute nothing.
  const controlledResults: CheckResult[] = [
    ...scanAuthControl(files, targetRoot),
    ...scanSecretsControl(files, targetRoot),
    ...scanApiRateLimitControl(files, targetRoot),
    ...scanSqlInjectionControl(files, targetRoot),
    ...scanSecurityHeadersControl(files, targetRoot),
    ...scanJwtAlgorithmControl(files, targetRoot),
    ...scanCryptoControl(files, targetRoot),
    ...scanAiPromptInjectionControl(files, targetRoot),
    ...scanPathTraversalControl(files, targetRoot),
    ...scanTransportSecurityControl(files, targetRoot),
    ...scanJwtExpiryControl(files, targetRoot),
    ...scanCorsControl(files, targetRoot),
  ];

  // Every other scanner module still speaks the legacy Finding/Pass shape.
  // Not yet migrated onto a Control definition — see the gap report for
  // what that migration involves per module.
  const legacyResults = [
    scanDependencies(targetRoot),
    scanLegalPolicy(targetRoot),
    scanAIDisclosure(files),
    scanWithSemgrep(targetRoot),
    scanOSVVulnerabilities(targetRoot),
    scanCodeQuality(files, targetRoot),
    scanDatabaseSecurity(files, targetRoot),
    scanApiSecurity(files, targetRoot),
    scanFrontendSecurity(files, targetRoot),
    scanAiSecurity(files, targetRoot),
    scanSessionJwt(files, targetRoot),
  ];

  const legacyFindings: Finding[] = legacyResults.flatMap((r) => r.findings);
  const legacyPassed: Pass[] = legacyResults.flatMap((r) => r.passed);

  // The legacy findings/passed arrays stay the aggregate everything else in
  // the codebase (scoring, the frontend, the badge) already reads — so the
  // controlled checks' FAIL/PASS results are folded back in. NOT_VERIFIED
  // has no legacy equivalent and is intentionally dropped from this array,
  // not forced into PASS or FAIL: it only exists in checkResults below.
  const findings: Finding[] = [
    ...legacyFindings,
    ...controlledResults.filter((r) => r.status === "FAIL").map(checkResultToFinding),
  ];
  const passed: Pass[] = [
    ...legacyPassed,
    ...controlledResults.filter((r) => r.status === "PASS").map(checkResultToPass),
  ];

  // checkResults is the unified, three-state view of the whole scan: the
  // controlled checks' native output, plus every legacy finding/pass
  // converted to a CheckResult (as FAIL/PASS — a module that hasn't been
  // migrated yet has no way to report NOT_VERIFIED for itself).
  const checkResults: CheckResult[] = [
    ...controlledResults,
    ...legacyFindings.map(findingToCheckResult),
    ...legacyPassed.map(passToCheckResult),
  ];

  // Calculate score using versioned config (excludes NOT_VERIFIED from penalty)
  const score = calculateScore(findings, SCORING_CONFIG);

  // Real confidence, driven by checkResults: no longer hardcoded to 100.
  // Drops whenever a controlled check reports NOT_VERIFIED (unrecognized
  // framework, an unreadable file) — previously that signal existed in the
  // three-state model's own tests but was never wired into an actual scan.
  const scoreConfidence = calculateConfidence(checkResults);

  const detectedTechnology = mapFrameworkToTechnology(detectFrameworks(targetRoot).primaryFramework) ?? null;

  return {
    scannedAt: new Date().toISOString(),
    target: path.basename(targetRoot),
    scannerVersion: SCANNER_VERSION,
    semgrepVersion: getSemgrepVersion(),
    controlLibraryVersion: getControlLibraryVersion(),
    controlVersions: getControlVersionsSnapshot(),
    scoringVersion: SCORING_CONFIG.version,
    score,
    scoreConfidence,
    findings,
    passed,
    checkResults,
    detectedTechnology,
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
