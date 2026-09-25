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
import { scanMultiTenantSecurityControl } from "./controls/checks/multiTenantSecurityControl";
import { scanCloudSecurityControl } from "./controls/checks/cloudSecurityControl";
import { scanAiCodeReviewControl } from "./controls/checks/aiCodeReviewControl";
import { scanSupplyChainControl } from "./controls/checks/supplyChainControl";
import { detectFrameworks } from "./frameworkDetection";
import { mapFrameworkToTechnology } from "./controls/technologyMap";
import "./controls"; // registers the control library (AUTH-001..008, SECRET-001..002, API-001..006, DB-001..003, BROWSER-001, CRYPTO-001, AI-001..005, INPUT-001..004, NET-001, DEPS-001, LEGAL-001..004, OSV-001, CQ-001..007, FE-001..004, PAY-001..004, CICD-001..003, MT-001..002, CLOUD-001..003, AICODE-001..002, SUPPLY-001..002, ...)
import { getControlLibraryVersion, getControlVersionsSnapshot } from "./controls";
import { SCANNER_VERSION, type CheckResult, type Finding, type Pass, type ScanReport } from "./types";
import { getSemgrepVersion } from "./initialization";
import { SCORING_CONFIG, calculateScore, calculateConfidence } from "./scoringConfig";
import { checkResultToFinding, checkResultToPass, findingToCheckResult, passToCheckResult, generateCheckId } from "./threeStateModel";

const SCANNED_EXTENSIONS = [".js", ".ts", ".jsx", ".tsx", ".env", ".json", ".yml", ".yaml", ".tf", "dockerfile"];

/**
 * Every control below was written and tested against fixture repos, not the
 * unbounded variety of real-world codebases a customer actually scans — a
 * huge lockfile, an unusual file encoding, a package.json shape a control's
 * parser didn't anticipate. Before this wrapper, one control throwing on
 * real-world input took the *entire* scan down (runScan() rethrew, the
 * queue recorded the whole thing as FAILED, and the customer got zero
 * results for it) — the exact "OSV-001 used to have no try/catch around its
 * DB query and could abort the whole scan" defect class documented in
 * osvVulnerabilityControl.ts's own comment, except unfixed for every other
 * control here. Isolating each call means one control's real-world bug
 * costs that one control (reported honestly as NOT_VERIFIED, with the
 * actual error attached) instead of the customer's whole scan.
 */
function runControlSafely(label: string, fn: () => CheckResult[]): CheckResult[] {
  try {
    return fn();
  } catch (err) {
    const message = (err as Error).message;
    console.error(`[scanner] ${label} threw and was skipped: ${message}`);
    return [
      {
        checkId: generateCheckId("Configuration", `${label}:internal-error`),
        status: "NOT_VERIFIED",
        category: "Configuration",
        title: `${label} could not complete`,
        detail: `This check hit an internal error on this codebase and was skipped rather than failing the whole scan: ${message}`,
        confidence: 0,
        detectionMethod: "unknown",
      },
    ];
  }
}

export function runScan(targetPath: string): ScanReport {
  const targetRoot = path.resolve(targetPath);
  const files = walk(targetRoot, SCANNED_EXTENSIONS);

  // Checks migrated onto the control library (see scanner/controls/) produce
  // CheckResult directly, including NOT_VERIFIED where the old
  // Finding/Pass-only modules could only silently contribute nothing.
  const controlledResults: CheckResult[] = [
    ...runControlSafely("AUTH", () => scanAuthControl(files, targetRoot)),
    ...runControlSafely("SECRET-001..002", () => scanSecretsControl(files, targetRoot)),
    ...runControlSafely("API rate limit", () => scanApiRateLimitControl(files, targetRoot)),
    ...runControlSafely("SQL injection", () => scanSqlInjectionControl(files, targetRoot)),
    ...runControlSafely("Security headers", () => scanSecurityHeadersControl(files, targetRoot)),
    ...runControlSafely("JWT algorithm", () => scanJwtAlgorithmControl(files, targetRoot)),
    ...runControlSafely("CRYPTO-001", () => scanCryptoControl(files, targetRoot)),
    ...runControlSafely("AI prompt injection", () => scanAiPromptInjectionControl(files, targetRoot)),
    ...runControlSafely("Path traversal", () => scanPathTraversalControl(files, targetRoot)),
    ...runControlSafely("NET-001 transport security", () => scanTransportSecurityControl(files, targetRoot)),
    ...runControlSafely("JWT expiry", () => scanJwtExpiryControl(files, targetRoot)),
    ...runControlSafely("CORS", () => scanCorsControl(files, targetRoot)),
    ...runControlSafely("Cookie security", () => scanCookieSecurityControl(files, targetRoot)),
    ...runControlSafely("CSRF", () => scanCsrfControl(files, targetRoot)),
    ...runControlSafely("INPUT-001..004", () => scanInputValidationControl(files, targetRoot)),
    ...runControlSafely("Request size", () => scanRequestSizeControl(files, targetRoot)),
    ...runControlSafely("File upload", () => scanFileUploadControl(files, targetRoot)),
    ...runControlSafely("Deserialization", () => scanDeserializationControl(files, targetRoot)),
    ...runControlSafely("DB credential exposure", () => scanDbCredentialExposureControl(files, targetRoot)),
    ...runControlSafely("Parameterized query", () => scanParameterizedQueryControl(files, targetRoot)),
    ...runControlSafely("Refresh token", () => scanRefreshTokenControl(files, targetRoot)),
    ...runControlSafely("Session store", () => scanSessionStoreControl(files, targetRoot)),
    ...runControlSafely("Session expiration", () => scanSessionExpirationControl(files, targetRoot)),
    ...runControlSafely("Logout invalidation", () => scanLogoutInvalidationControl(files, targetRoot)),
    ...runControlSafely("AI cost limits", () => scanAiCostLimitsControl(files, targetRoot)),
    ...runControlSafely("AI tool execution", () => scanAiToolExecutionControl(files, targetRoot)),
    ...runControlSafely("AI output validation", () => scanAiOutputValidationControl(files, targetRoot)),
    ...runControlSafely("DEPS-001 lockfile", () => scanDependencyLockfileControl(targetRoot)),
    ...runControlSafely("LEGAL-001..004", () => scanLegalPolicyControl(targetRoot)),
    ...runControlSafely("AI content disclosure", () => scanAiContentDisclosureControl(files, targetRoot)),
    ...runControlSafely("Semgrep", () => scanSemgrepControl(targetRoot)),
    ...runControlSafely("OSV-001", () => scanOsvVulnerabilityControl(targetRoot)),
    ...runControlSafely("CQ-001..007 code quality", () => scanCodeQualityControl(files, targetRoot)),
    ...runControlSafely("FE-001..004 frontend security", () => scanFrontendSecurityControl(files, targetRoot)),
    ...runControlSafely("PAY-001..004 payment security", () => scanPaymentSecurityControl(files, targetRoot)),
    ...runControlSafely("CICD-001..003", () => scanCicdSecurityControl(files, targetRoot)),
    ...runControlSafely("MT-001..002 multi-tenant security", () => scanMultiTenantSecurityControl(files, targetRoot)),
    ...runControlSafely("CLOUD-001..003", () => scanCloudSecurityControl(files, targetRoot)),
    ...runControlSafely("AICODE-001..002", () => scanAiCodeReviewControl(files, targetRoot)),
    ...runControlSafely("SUPPLY-001..002", () => scanSupplyChainControl(targetRoot)),
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

  // Technology detection is a nice-to-have (it only steers which fix
  // recommendation a finding shows) — it must never be able to take the
  // whole scan down the way an unwrapped control call used to.
  let detectedTechnology: string | null = null;
  try {
    detectedTechnology = mapFrameworkToTechnology(detectFrameworks(targetRoot).primaryFramework) ?? null;
  } catch (err) {
    console.error(`[scanner] technology detection threw and was skipped: ${(err as Error).message}`);
  }

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
