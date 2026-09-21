import { getLatestScan } from "./scans";
import { listAlerts } from "./alerts";

export type BadgeStatus = "protected" | "caution" | "critical" | "unknown";

export interface BadgeState {
  status: BadgeStatus;
  label: string;
  lastScannedAt: string | null;
  score: number | null;
}

const RECENT_ALERT_WINDOW_MS = 48 * 60 * 60 * 1000; // 48 hours

/**
 * What the badge actually shows is a real read of project state, not a
 * decoration: the latest Tier 1 scan result plus whether Tier 2 has caught
 * anything critical recently. Either one being bad makes the badge bad —
 * a clean scan from a month ago doesn't mean much if an alert fired an hour ago.
 */
export async function computeBadgeState(projectId: string): Promise<BadgeState> {
  const latestScan = await getLatestScan(projectId);
  const alerts = await listAlerts(projectId);
  const recentCriticalAlert = alerts.some(
    (a) => a.severity === "critical" && Date.now() - new Date(a.occurredAt).getTime() <= RECENT_ALERT_WINDOW_MS
  );

  if (!latestScan) {
    return { status: "unknown", label: "Not yet scanned", lastScannedAt: null, score: null };
  }

  if (latestScan.criticalCount > 0 || recentCriticalAlert) {
    return {
      status: "critical",
      label: "Issues found",
      lastScannedAt: latestScan.scannedAt,
      score: latestScan.score,
    };
  }

  const mediumOrAbove = latestScan.report.summary.medium + latestScan.report.summary.high;
  if (mediumOrAbove > 0) {
    return {
      status: "caution",
      label: "Minor issues",
      lastScannedAt: latestScan.scannedAt,
      score: latestScan.score,
    };
  }

  return { status: "protected", label: "Protected", lastScannedAt: latestScan.scannedAt, score: latestScan.score };
}

const COLORS: Record<BadgeStatus, string> = {
  protected: "#3F7A52",
  caution: "#B9822A",
  critical: "#B23A2E",
  unknown: "#8A8578",
};

export function renderBadgeSVG(state: BadgeState): string {
  const color = COLORS[state.status];
  const rightText = state.label;
  const leftText = "nettle";

  // Fixed-width, shields.io-style flat badge — deliberately simple, hand-
  // measured widths rather than a text-measurement library, since the label
  // set is small and fixed.
  const leftWidth = 50;
  const rightWidth = { protected: 62, caution: 74, critical: 66, unknown: 82 }[state.status];
  const totalWidth = leftWidth + rightWidth;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20" role="img" aria-label="${leftText}: ${rightText}">
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="${totalWidth}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${leftWidth}" height="20" fill="#2C4A5C"/>
    <rect x="${leftWidth}" width="${rightWidth}" height="20" fill="${color}"/>
    <rect width="${totalWidth}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="${leftWidth / 2}" y="14">${leftText}</text>
    <text x="${leftWidth + rightWidth / 2}" y="14">${rightText}</text>
  </g>
</svg>`;
}
