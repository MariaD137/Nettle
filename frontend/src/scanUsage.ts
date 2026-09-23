import type { QuotaState } from "./api";

/**
 * Turns a QuotaState into the exact copy the pricing spec calls for (§18):
 * FREE ("Scanning is available on BUILD and PROTECT"), BUILD ("7 / 10",
 * "2 scans remaining", or "Scan limit reached" at zero), PROTECT ("Unlimited
 * / fair-use scanning"). Never a fabricated number — quota always comes
 * from the real backend state (GET /api/overview's quota field).
 */
export interface ScanUsageCopy {
  headline: string;
  detail: string;
  critical: boolean;
}

export function scanUsageCopy(quota: QuotaState): ScanUsageCopy {
  if (quota.limit === null) {
    return { headline: "Unlimited", detail: "Unlimited, fair-use scanning", critical: false };
  }
  if (quota.limit === 0) {
    return {
      headline: "—",
      detail: "Scanning is available on BUILD and PROTECT.",
      critical: false,
    };
  }
  if (quota.exhausted) {
    return {
      headline: "0",
      detail: "Scan limit reached. Upgrade to PROTECT for unlimited, fair-use scanning.",
      critical: true,
    };
  }
  return {
    headline: String(quota.remaining),
    detail: `${quota.used} / ${quota.limit} scans this billing period`,
    critical: (quota.remaining ?? 0) <= 2,
  };
}
