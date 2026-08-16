import { execFileSync } from "child_process";

/**
 * Scanner initialization: verify dependencies and record metadata at startup.
 */

export interface ScannerMetadata {
  semgrepAvailable: boolean;
  semgrepVersion?: string;
  initializationTime: string;
}

let scannerMetadata: ScannerMetadata | null = null;

/**
 * Initialize the scanner at API startup. Checks for required tools.
 * Does not crash if tools are missing — analyzers will handle gracefully
 * by returning NOT_VERIFIED results.
 */
export function initializeScanner(): ScannerMetadata {
  if (scannerMetadata) return scannerMetadata;

  const metadata: ScannerMetadata = {
    semgrepAvailable: false,
    initializationTime: new Date().toISOString(),
  };

  // Verify Semgrep is available and capture version
  try {
    const versionOutput = execFileSync("semgrep", ["--version"], {
      encoding: "utf8",
      timeout: 5_000,
    });
    // Output is like "1.65.0\n"
    const version = versionOutput.trim().split("\n")[0];
    metadata.semgrepAvailable = true;
    metadata.semgrepVersion = version;
    console.log(`✓ Semgrep ${version} initialized`);
  } catch (err) {
    console.warn(`⚠ Semgrep not available: ${(err as Error).message}`);
    // This is not fatal — analyzers will degrade gracefully
  }

  scannerMetadata = metadata;
  return metadata;
}

/**
 * Get the cached scanner metadata (call initializeScanner first).
 */
export function getScannerMetadata(): ScannerMetadata {
  if (!scannerMetadata) {
    throw new Error("Scanner not initialized — call initializeScanner() at startup");
  }
  return scannerMetadata;
}

/**
 * Check if Semgrep is available (useful for tests and feature flags).
 */
export function isSemgrepAvailable(): boolean {
  return scannerMetadata?.semgrepAvailable ?? false;
}

/**
 * Get Semgrep version if available.
 */
export function getSemgrepVersion(): string | undefined {
  return scannerMetadata?.semgrepVersion;
}
