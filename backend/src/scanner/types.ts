export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type FindingCategory =
  | "Security"
  | "Dependencies"
  | "Authentication"
  | "Legal & Policy"
  | "AI Disclosure"
  | "Configuration"
  | "Cryptography"
  | "Database"
  | "API Security"
  | "Frontend Security"
  | "Code Quality"
  | "Supply Chain"
  | "Session Management";

export interface Finding {
  severity: Severity;
  category: FindingCategory;
  title: string;
  detail: string;
  file: string | null;
  remediation: string | null;
}

export interface Pass {
  category: FindingCategory;
  title: string;
}

export interface ScanReport {
  scannedAt: string;
  target: string;
  score: number;
  findings: Finding[];
  passed: Pass[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    clear: number;
  };
}
