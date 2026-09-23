import path from "path";
import { walk } from "./walk";
import { scanSecretsControl } from "./secrets";
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
import { scanCookieSecurityControl } from "./controls/checks/cookieSecurityControl";
import { scanCsrfControl } from "./controls/checks/csrfControl";
import { scanInputValidationControl } from "./controls/checks/inputValidationControl";
import { scanRequestSizeControl } from "./controls/checks/requestSizeControl";
import { scanFileUploadControl } from "./controls/checks/fileUploadControl";
import { scanDeserializationControl } from "./controls/checks/deserializationControl";
import { scanDbCredentialExposureControl } from "./controls/checks/dbCredentialExposureControl";
import { scanParameterizedQueryControl } from "./controls/checks/parameterizedQueryControl";
import { scanRefreshTokenControl } from "./controls/checks/refreshTokenControl";
import { scanSessionStoreControl } from "./controls/checks/sessionStoreControl";
import { scanSessionExpirationControl } from "./controls/checks/sessionExpirationControl";
import { scanLogoutInvalidationControl } from "./controls/checks/logoutInvalidationControl";
import { scanAiCostLimitsControl } from "./controls/checks/aiCostLimitsControl";
import { scanAiToolExecutionControl } from "./controls/checks/aiToolExecutionControl";
import { scanAiOutputValidationControl } from "./controls/checks/aiOutputValidationControl";
import { scanDependencyLockfileControl } from "./controls/checks/dependencyLockfileControl";
import { scanLegalPolicyControl } from "./controls/checks/legalPolicyControl";
import { scanAiContentDisclosureControl } from "./controls/checks/aiContentDisclosureControl";
import { scanSemgrepControl } from "./controls/checks/semgrepControl";
import { scanOsvVulnerabilityControl } from "./controls/checks/osvVulnerabilityControl";
import { scanCodeQualityControl } from "./controls/checks/codeQualityControl";
import { scanFrontendSecurityControl } from "./controls/checks/frontendSecurityControl";
import { scanPaymentSecurityControl } from "./controls/checks/paymentSecurityControl";
import { scanCicdSecurityControl } from "./controls/checks/cicdSecurityControl";
import { detectFrameworks } from "./frameworkDetection";
import { mapFrameworkToTechnology } from "./controls/technologyMap";
import "./controls"; // registers the control library (AUTH-001..008, SECRET-001..002, API-001..006, DB-001..003, BROWSER-001, CRYPTO-001, AI-001..005, INPUT-001..004, NET-001, DEPS-001, LEGAL-001..004, OSV-001, CQ-001..007, FE-001..004, PAY-001..004, CICD-001..003, ...)
import { getControlLibraryVersion, getControlVersionsSnapshot } from "./controls";
import { SCANNER_VERSION, type CheckResult, type Finding, type Pass, type ScanReport } from "./types";
import { getSemgrepVersion } from "./initialization";
import { SCORING_CONFIG, calculateScore, calculateConfidence } from "./scoringConfig";
import { checkResultToFinding, checkResultToPass, findingToCheckResult, passToCheckResult } from "./threeStateModel";

const SCANNED_EXTENSIONS = [".js", ".ts", ".jsx", ".tsx", ".env", ".json", ".yml", ".yaml"];

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
    ...scanCookieSecurityControl(files, targetRoot),
    ...scanCsrfControl(files, targetRoot),
    ...scanInputValidationControl(files, targetRoot),
    ...scanRequestSizeControl(files, targetRoot),
    ...scanFileUploadControl(files, targetRoot),
    ...scanDeserializationControl(files, targetRoot),
    ...scanDbCredentialExposureControl(files, targetRoot),
    ...scanParameterizedQueryControl(files, targetRoot),
    ...scanRefreshTokenControl(files, targetRoot),
    ...scanSessionStoreControl(files, targetRoot),
    ...scanSessionExpirationControl(files, targetRoot),
    ...scanLogoutInvalidationControl(files, targetRoot),
    ...scanAiCostLimitsControl(files, targetRoot),
    ...scanAiToolExecutionControl(files, targetRoot),
    ...scanAiOutputValidationControl(files, targetRoot),
    ...scanDependencyLockfileControl(targetRoot),
    ...scanLegalPolicyControl(targetRoot),
    ...scanAiContentDisclosureControl(files, targetRoot),
    ...scanSemgrepControl(targetRoot),
    ...scanOsvVulnerabilityControl(targetRoot),
    ...scanCodeQualityControl(files, targetRoot),
    ...scanFrontendSecurityControl(files, targetRoot),
    ...scanPaymentSecurityControl(files, targetRoot),
    ...scanCicdSecurityControl(files, targetRoot),
  ];

  // Every legacy Finding/Pass-shaped scanner module (apiSecurity.ts,
  // databaseSecurity.ts, sessionJwt.ts, aiSecurity.ts, dependencies.ts,
  // legalPolicy.ts, aiDisclosure.ts, semgrepScanner.ts,
  // osvVulnerabilities.ts, codeQuality.ts, and frontendSecurity.ts) is now
  // migrated onto the control library and deleted — Phase A is complete.
  // legacyResults is kept as an empty array, not removed outright, since
  // findings/passed/checkResults below still read it; retiring the
  // Finding/Pass plumbing itself is a separate, larger change than this
  // migration.
  const legacyResults: { findings: Finding[]; passed: Pass[] }[] = [];

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
