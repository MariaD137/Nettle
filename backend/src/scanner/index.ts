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
import { SCANNER_VERSION, type Finding, type Pass, type ScanReport, type ScanType } from "./types";
import { getSemgrepVersion } from "./initialization";
import { SCORING_CONFIG, calculateScore, calculateConfidence } from "./scoringConfig";
import { correlateAttackChains } from "./attackChains";
import { scanTerraformSecurity } from "./terraformSecurity";
import { scanDockerSecurity } from "./dockerSecurity";
import { scanKubernetesSecurity } from "./kubernetesSecurity";
import { scanCicdSecurity } from "./cicdSecurity";
import { enrichFindings } from "./evidence";

const SCANNED_EXTENSIONS = [".js", ".ts", ".jsx", ".tsx", ".env", ".json", ".tf", ".yaml", ".yml", "dockerfile"];

export interface ScanStepEvent {
  type: "step-start" | "step-complete";
  stepId: string;
  stepLabel: string;
  index: number;
  total: number;
}

export type ScanProgressCallback = (event: ScanStepEvent) => void;

interface ScanStep {
  id: string;
  label: string;
  run: () => { findings: Finding[]; passed: Pass[] };
}

/**
 * The canonical, ordered list of source-scan steps and their display
 * labels — the single source of truth for both runScan's execution order
 * and anything that wants to show a step-by-step progress list (the async
 * scan-job worker, in particular) before or during a real scan. Exported
 * so callers never have to hardcode a second copy of this list that could
 * drift out of sync with what actually runs.
 */
export function sourceScanSteps(files: string[], targetRoot: string): ScanStep[] {
  return [
    { id: "secrets", label: "Scanning for hardcoded secrets", run: () => scanSecrets(files, targetRoot) },
    { id: "dependencies", label: "Checking dependency lockfile", run: () => scanDependencies(targetRoot) },
    { id: "legal-policy", label: "Checking legal & policy documents", run: () => scanLegalPolicy(files, targetRoot) },
    { id: "ai-disclosure", label: "Checking AI content disclosure", run: () => scanAIDisclosure(files) },
    { id: "auth-heuristic", label: "Checking for authentication (file-level)", run: () => scanAuthHeuristic(files, targetRoot) },
    { id: "auth-analysis", label: "Checking for authentication (per-route)", run: () => scanAuthAnalysis(files, targetRoot) },
    { id: "semgrep", label: "Running static analysis (Semgrep)", run: () => scanWithSemgrep(targetRoot) },
    { id: "osv", label: "Checking dependencies for known vulnerabilities", run: () => scanOSVVulnerabilities(targetRoot) },
    { id: "security-headers", label: "Checking security headers", run: () => scanSecurityHeaders(files, targetRoot) },
    { id: "code-quality", label: "Checking code quality", run: () => scanCodeQuality(files, targetRoot) },
    { id: "crypto", label: "Checking cryptography usage", run: () => scanCrypto(files, targetRoot) },
    { id: "database", label: "Checking database security", run: () => scanDatabaseSecurity(files, targetRoot) },
    { id: "api-security", label: "Checking API security", run: () => scanApiSecurity(files, targetRoot) },
    { id: "frontend-security", label: "Checking frontend security", run: () => scanFrontendSecurity(files, targetRoot) },
    { id: "ai-security", label: "Checking AI/LLM security", run: () => scanAiSecurity(files, targetRoot) },
    { id: "session-jwt", label: "Checking session & JWT handling", run: () => scanSessionJwt(files, targetRoot) },
    { id: "terraform", label: "Checking Terraform configuration", run: () => scanTerraformSecurity(files, targetRoot) },
    { id: "docker", label: "Checking Docker configuration", run: () => scanDockerSecurity(files, targetRoot) },
    { id: "kubernetes", label: "Checking Kubernetes configuration", run: () => scanKubernetesSecurity(files, targetRoot) },
    { id: "cicd", label: "Checking CI/CD configuration", run: () => scanCicdSecurity(files, targetRoot) },
  ];
}

export function runScan(targetPath: string, scanType?: ScanType, onProgress?: ScanProgressCallback): ScanReport {
  const targetRoot = path.resolve(targetPath);
  const files = walk(targetRoot, SCANNED_EXTENSIONS);

  const steps = sourceScanSteps(files, targetRoot);
  const results: { findings: Finding[]; passed: Pass[] }[] = [];
  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    onProgress?.({ type: "step-start", stepId: step.id, stepLabel: step.label, index: i, total: steps.length });
    results.push(step.run());
    onProgress?.({ type: "step-complete", stepId: step.id, stepLabel: step.label, index: i, total: steps.length });
  }

  const findings = enrichFindings(results.flatMap((r) => r.findings), targetRoot);
  const passed = results.flatMap((r) => r.passed);
  const attackChains = correlateAttackChains(findings);

  // Calculate score using versioned config (excludes NOT_VERIFIED from penalty)
  const score = calculateScore(findings, SCORING_CONFIG);

  // Calculate confidence: what percentage of checks completed?
  // For now, based on legacy model (we'll enhance when migrating to CheckResult)
  // Confidence = 100% until we migrate to checkResults with NOT_VERIFIED
  const scoreConfidence = 100;

  return {
    scannedAt: new Date().toISOString(),
    target: path.basename(targetRoot),
    scanType,
    scannerVersion: SCANNER_VERSION,
    semgrepVersion: getSemgrepVersion(),
    score,
    scoreConfidence,
    findings,
    passed,
    attackChains,
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

/**
 * Runs the URL check set (external HTTP/TLS/header observation — see
 * urlSecurity.ts) and wraps it in the same ScanReport shape as runScan,
 * reusing the same score/summary pipeline. This is deliberately a
 * separate function rather than a branch inside runScan: a URL scan has
 * no filesystem to walk and no files array, so trying to force it through
 * the same code path would mean threading a lot of "this doesn't apply
 * here" special-casing through file-based scanner internals for no real
 * benefit — reporting through one shared *shape* is what actually matters
 * for the rest of the app (scoring, storage, comparison, badge).
 */
export const URL_SCAN_STEPS: { id: string; label: string }[] = [{ id: "url-checks", label: "Running external URL checks" }];

export async function runUrlScan(targetUrl: string, onProgress?: ScanProgressCallback): Promise<ScanReport> {
  const { scanUrl } = await import("./urlSecurity");
  const [{ id: stepId, label: stepLabel }] = URL_SCAN_STEPS;
  onProgress?.({ type: "step-start", stepId, stepLabel, index: 0, total: 1 });
  const result = await scanUrl(targetUrl);
  onProgress?.({ type: "step-complete", stepId, stepLabel, index: 0, total: 1 });

  // No targetRoot: a URL scan has no filesystem to read code context from,
  // but every finding still gets a stable ruleId for search/filtering.
  enrichFindings(result.findings);
  const score = calculateScore(result.findings, SCORING_CONFIG);
  const attackChains = correlateAttackChains(result.findings);

  return {
    scannedAt: new Date().toISOString(),
    target: result.finalUrl,
    scanType: "URL",
    scannerVersion: SCANNER_VERSION,
    score,
    scoreConfidence: 100,
    findings: result.findings,
    passed: result.passed,
    attackChains,
    summary: {
      critical: result.findings.filter((f) => f.severity === "critical").length,
      high: result.findings.filter((f) => f.severity === "high").length,
      medium: result.findings.filter((f) => f.severity === "medium").length,
      low: result.findings.filter((f) => f.severity === "low").length,
      info: result.findings.filter((f) => f.severity === "info").length,
      clear: result.passed.length,
    },
  };
}

export type { ScanReport, ScanType, Finding, Pass, Severity, AttackChain } from "./types";
export { SsrfBlockedError } from "./ssrfSafeFetch";
export { UrlScanUnreachableError } from "./urlSecurity";
