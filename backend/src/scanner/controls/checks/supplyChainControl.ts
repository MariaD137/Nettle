import fs from "fs";
import path from "path";
import type { CheckResult } from "../../types";
import { generateCheckId } from "../../threeStateModel";

/**
 * A modest, curated list of extremely well-known npm packages — real-world
 * typosquatting targets, not an attempt at npm-registry-wide coverage. Kept
 * deliberately short and unambiguous (see checkTyposquat's own edit-distance
 * threshold) rather than large, to keep the false-positive rate low: a
 * bigger list risks colliding with legitimate near-variant package names
 * (globby vs glob, bcryptjs vs bcrypt) the way a longer or looser-matching
 * list would.
 */
const POPULAR_PACKAGES = [
  "lodash", "express", "axios", "chalk", "commander", "moment", "debug",
  "request", "colors", "mongoose", "bcrypt", "dotenv", "jsonwebtoken",
  "nodemon", "prettier", "eslint", "webpack", "typescript", "jquery",
  "cors", "uuid", "semver", "minimist", "yargs", "rimraf", "glob",
  "event-stream", "socket.io", "body-parser", "cross-env",
];

/**
 * Damerau-Levenshtein edit distance (optimal string alignment variant):
 * insert/delete/substitute/adjacent-transpose, each cost 1. Transposition
 * matters here specifically because the classic typosquat example
 * (lodash -> lodahs) is a transposition, not a substitution — under plain
 * Levenshtein it's distance 2, which a distance-1 threshold would miss.
 */
function editDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + 1);
      }
    }
  }
  return dp[m][n];
}

/**
 * Returns the well-known package name a given dependency name is a
 * suspected typosquat of, or null. A strict distance-1 threshold (not 2):
 * verified directly against real popular near-variant package names
 * (globby, bcryptjs, uuidv4, express-session, react-dom, vuex, ...) that a
 * looser distance-2 threshold false-positived on during this control's
 * design — distance 1 catches the intended typo examples while leaving
 * every one of those legitimate packages alone.
 */
function checkTyposquat(name: string): string | null {
  if (POPULAR_PACKAGES.includes(name)) return null;
  for (const popular of POPULAR_PACKAGES) {
    if (editDistance(name, popular) === 1) return popular;
  }
  return null;
}

const NON_REGISTRY_REF_PATTERN = /^(git(\+https?|\+ssh)?:\/\/|https?:\/\/|github:|[\w-]+\/[\w.-]+(#.*)?$)/i;
const TARBALL_PATTERN = /\.(tgz|tar\.gz)$/i;

function isNonRegistryRef(spec: string): boolean {
  return NON_REGISTRY_REF_PATTERN.test(spec) || TARBALL_PATTERN.test(spec);
}

/**
 * SUPPLY-001/002, wired to the control library. Sixth and final Phase B
 * category for this pass (master spec §16: Supply Chain, beyond the
 * lockfile/known-vulnerability coverage DEPS-001/OSV-001 already provide).
 * "Supply Chain" has been a FindingCategory since before this Phase B
 * effort started but had no control using it yet, confirmed via grep.
 *
 * Both read package.json directly (dependencies + devDependencies merged
 * -- a typo or a non-registry reference is equally real in either), and
 * both are NOT_VERIFIED, not silently absent, when no package.json exists
 * -- matching DEPS-001's precedent for the same underlying condition.
 */
export function scanSupplyChainControl(targetRoot: string): CheckResult[] {
  const pkgPath = path.join(targetRoot, "package.json");
  if (!fs.existsSync(pkgPath)) {
    return [
      notVerified("SUPPLY-001", "No package.json found — dependency names could not be checked for typosquatting."),
      notVerified("SUPPLY-002", "No package.json found — dependency sources could not be checked."),
    ];
  }

  let pkg: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  try {
    pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
  } catch (err) {
    const detail = `package.json could not be parsed: ${(err as Error).message}`;
    return [notVerified("SUPPLY-001", detail), notVerified("SUPPLY-002", detail)];
  }

  const deps: Record<string, string> = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
  const results: CheckResult[] = [];

  let typosquatFound = false;
  let nonRegistryFound = false;

  for (const [name, spec] of Object.entries(deps)) {
    const suspectedTarget = checkTyposquat(name);
    if (suspectedTarget) {
      typosquatFound = true;
      results.push({
        checkId: generateCheckId("Supply Chain", "SUPPLY-001:fail", name),
        status: "FAIL",
        category: "Supply Chain",
        title: `Dependency name "${name}" resembles the well-known package "${suspectedTarget}"`,
        detail: `"${name}" is one edit away from "${suspectedTarget}" — this may be a typo, or a deliberately-published typosquat.`,
        severity: "high",
        file: "package.json",
        confidence: 70,
        detectionMethod: "heuristic",
        remediation: `Confirm "${name}" is the package you intended. If it was meant to be "${suspectedTarget}", correct the name and re-run npm install.`,
        controlKey: "SUPPLY-001",
      });
    }

    if (isNonRegistryRef(spec)) {
      nonRegistryFound = true;
      results.push({
        checkId: generateCheckId("Supply Chain", "SUPPLY-002:fail", name),
        status: "FAIL",
        category: "Supply Chain",
        title: `Dependency "${name}" is installed from a git/URL reference, not the registry`,
        detail: `"${name}" is specified as "${spec}", bypassing the npm registry's own integrity and version-history guarantees.`,
        severity: "medium",
        file: "package.json",
        confidence: 90,
        detectionMethod: "regex",
        remediation: "Publish the dependency to the npm registry, or pin the git reference to an immutable commit SHA rather than a branch or tag.",
        controlKey: "SUPPLY-002",
      });
    }
  }

  if (!typosquatFound) {
    results.push(pass("SUPPLY-001", "No dependency name resembles a well-known package"));
  }
  if (!nonRegistryFound) {
    results.push(pass("SUPPLY-002", "All dependencies are installed from the registry"));
  }

  return results;
}

function pass(controlKey: string, title: string): CheckResult {
  return {
    checkId: generateCheckId("Supply Chain", `${controlKey}:pass`),
    status: "PASS",
    category: "Supply Chain",
    title,
    confidence: 80,
    detectionMethod: "heuristic",
    controlKey,
  };
}

function notVerified(controlKey: string, title: string): CheckResult {
  return {
    checkId: generateCheckId("Supply Chain", `${controlKey}:not-verified`),
    status: "NOT_VERIFIED",
    category: "Supply Chain",
    title,
    confidence: 0,
    detectionMethod: "heuristic",
    controlKey,
  };
}
