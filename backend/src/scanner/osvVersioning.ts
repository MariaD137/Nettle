/**
 * OSV versioning: track vulnerability database metadata.
 * Ensures reproducibility and clarity about which vulnerabilities are known.
 */

export interface OSVDatabaseMetadata {
  version: string; // Database version (e.g., "2026-08-16")
  fetchedAt: string; // ISO timestamp
  source: "npm" | "pypi" | "bundled" | "offline";
  lastUpdated: string; // Database's own timestamp
  recordCount: number; // How many vulnerability records
  confidence: number; // 0-100: how recent/complete is the data
}

export interface VulnerabilityRecord {
  id: string; // CVE or advisory ID
  affectedPackage: string;
  affectedVersions: string[];
  severity: "critical" | "high" | "medium" | "low";
  cvss: number; // 0-10 score
  detectionMethod: string; // "npm audit", "pip check", "osv-scanner"
  cwe: string[]; // CWE IDs
  description: string;
}

/**
 * OSV database state.
 * Singleton tracking the current vulnerability database.
 */
class OSVDatabase {
  private metadata: OSVDatabaseMetadata | null = null;
  private records: Map<string, VulnerabilityRecord[]> = new Map();

  /**
   * Initialize or update database metadata.
   */
  setMetadata(metadata: OSVDatabaseMetadata): void {
    this.metadata = metadata;
  }

  /**
   * Get current database metadata.
   */
  getMetadata(): OSVDatabaseMetadata | null {
    return this.metadata;
  }

  /**
   * Register a vulnerability record.
   */
  addRecord(record: VulnerabilityRecord): void {
    const key = `${record.affectedPackage}@${record.id}`;
    if (!this.records.has(key)) {
      this.records.set(key, []);
    }
    this.records.get(key)!.push(record);
  }

  /**
   * Lookup vulnerabilities for a package.
   */
  getVulnerabilities(packageName: string, version?: string): VulnerabilityRecord[] {
    const vulns: VulnerabilityRecord[] = [];

    for (const [_, records] of this.records) {
      for (const record of records) {
        if (record.affectedPackage === packageName) {
          if (!version || record.affectedVersions.includes(version)) {
            vulns.push(record);
          }
        }
      }
    }

    return vulns;
  }

  /**
   * Get vulnerability statistics.
   */
  getStats(): {
    totalRecords: number;
    bySeverity: Record<string, number>;
    bySource: Record<string, number>;
  } {
    const stats = {
      totalRecords: this.records.size,
      bySeverity: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      },
      bySource: {} as Record<string, number>,
    };

    for (const [_, records] of this.records) {
      for (const record of records) {
        stats.bySeverity[record.severity]++;
        stats.bySource[record.detectionMethod] = (stats.bySource[record.detectionMethod] || 0) + 1;
      }
    }

    return stats;
  }

  /**
   * Clear all records.
   */
  clear(): void {
    this.records.clear();
    this.metadata = null;
  }
}

/**
 * Global OSV database singleton.
 */
let osvDatabase: OSVDatabase | null = null;

/**
 * Get or create the global OSV database.
 */
export function getOSVDatabase(): OSVDatabase {
  if (!osvDatabase) {
    osvDatabase = new OSVDatabase();
  }
  return osvDatabase;
}

/**
 * Initialize OSV database with metadata.
 */
export function initializeOSVDatabase(metadata: OSVDatabaseMetadata): void {
  const db = getOSVDatabase();
  db.setMetadata(metadata);
}

/**
 * Create default offline database metadata.
 * Used when no live OSV source is available.
 */
export function createOfflineDatabaseMetadata(): OSVDatabaseMetadata {
  return {
    version: "2026-08-16-offline",
    fetchedAt: new Date().toISOString(),
    source: "offline",
    lastUpdated: new Date().toISOString(),
    recordCount: 0,
    confidence: 50, // Lower confidence for offline/cached data
  };
}

/**
 * Create npm-based database metadata.
 */
export function createNpmDatabaseMetadata(npmAuditData: any): OSVDatabaseMetadata {
  return {
    version: npmAuditData.version || "1.0.0",
    fetchedAt: new Date().toISOString(),
    source: "npm",
    lastUpdated: npmAuditData.lastUpdated || new Date().toISOString(),
    recordCount: npmAuditData.recordCount || 0,
    confidence: 90, // High confidence for npm audit
  };
}

/**
 * Create PyPI-based database metadata.
 */
export function createPyPIDatabaseMetadata(pypiData: any): OSVDatabaseMetadata {
  return {
    version: pypiData.version || "1.0.0",
    fetchedAt: new Date().toISOString(),
    source: "pypi",
    lastUpdated: pypiData.lastUpdated || new Date().toISOString(),
    recordCount: pypiData.recordCount || 0,
    confidence: 85, // High confidence for PyPI data
  };
}

/**
 * Check if OSV database is fresh (updated within N days).
 */
export function isDatabaseFresh(maxAgeDays: number = 7): boolean {
  const db = getOSVDatabase();
  const metadata = db.getMetadata();

  if (!metadata) return false;

  const lastUpdate = new Date(metadata.lastUpdated);
  const now = new Date();
  const ageDays = (now.getTime() - lastUpdate.getTime()) / (1000 * 60 * 60 * 24);

  return ageDays <= maxAgeDays;
}

/**
 * Generate OSV versioning report.
 */
export function generateOSVReport(): string {
  const db = getOSVDatabase();
  const metadata = db.getMetadata();
  const stats = db.getStats();

  if (!metadata) {
    return "OSV database not initialized";
  }

  const freshness = isDatabaseFresh() ? "✓ Fresh" : "⚠ Stale";
  const confidentReport = `Confidence: ${metadata.confidence}%`;

  return `
OSV Database Report
===================
Version: ${metadata.version}
Source: ${metadata.source}
Fetched: ${new Date(metadata.fetchedAt).toISOString()}
Last Updated: ${new Date(metadata.lastUpdated).toISOString()}
Status: ${freshness}
${confidentReport}

Statistics
----------
Total Records: ${stats.totalRecords}
Critical: ${stats.bySeverity.critical}
High: ${stats.bySeverity.high}
Medium: ${stats.bySeverity.medium}
Low: ${stats.bySeverity.low}

Sources
-------
${Object.entries(stats.bySource)
  .map(([source, count]) => `${source}: ${count}`)
  .join("\n")}
  `.trim();
}

/**
 * Reset the global OSV database.
 */
export function resetOSVDatabase(): void {
  if (osvDatabase) {
    osvDatabase.clear();
    osvDatabase = null;
  }
}
