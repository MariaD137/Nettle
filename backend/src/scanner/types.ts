export type Severity = "critical" | "caution";

export interface Finding {
  severity: Severity;
  category: "Security" | "Legal & Policy" | "AI Disclosure";
  title: string;
  detail: string;
  file: string | null;
}

export interface Pass {
  category: Finding["category"];
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
    caution: number;
    clear: number;
  };
}
