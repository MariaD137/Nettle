/**
 * The single authoritative FREE / BUILD / PROTECT entitlement model.
 *
 * Every other file that needs to know what a plan is allowed to do calls a
 * function here rather than hardcoding `if (plan === "free")` — that
 * scattering is exactly what let the pre-pricing-rework code drift (see
 * projects.routes.ts's old PLAN_LIMITS table, duplicated and out of sync
 * with scanQuota.ts's SCAN_QUOTAS, before this file existed).
 *
 * This module answers "what does this plan allow" from an already-resolved
 * plan string. It deliberately does NOT resolve a User into a plan itself —
 * that's billing/subscription.ts's entitledPlan(), which already correctly
 * handles the canceled/past_due/unpaid-drops-to-free rule and is
 * extensively tested. Callers do:
 *
 *   const plan = entitledPlan(user);       // subscription.ts
 *   if (!canRunScan(plan)) { ...402... }   // this file
 *
 * never `user.plan` or `req.userPlan` directly — both are the *recorded*
 * plan (what was last purchased), not the *entitled* one (what's currently
 * paid up), and using either for an access decision is the exact bug
 * entitledPlan() exists to prevent.
 */

export type Plan = "free" | "build" | "protect";

export const PLANS: readonly Plan[] = ["free", "build", "protect"];

/** Anything not recognized as "build" or "protect" is treated as "free" — never as a crash or a silent bypass. */
export function normalizePlan(plan: string | null | undefined): Plan {
  return plan === "build" || plan === "protect" ? plan : "free";
}

interface PlanConfig {
  /** Scans allowed per billing period. null = unlimited/fair-use (PROTECT) — never a large arbitrary number standing in for "unlimited". */
  monthlyScanLimit: number | null;
  /** null = unlimited (PROTECT). */
  maxProjects: number | null;
  teamMemberLimit: number;
  /** Full findings, file-level evidence, remediation recommendations, rescan/verification — the paid report experience. */
  canUseFixCenter: boolean;
  /** CLI/CI `--fail-on` gating and scan history are the same underlying capability: being able to run and retain real scans at all. */
  canUseCiGating: boolean;
  hasScanHistory: boolean;
  hasTrustBadge: boolean;
  canUseContinuousMonitoring: boolean;
  canUseLiveAlerts: boolean;
  canUseApi: boolean;
  hasPrioritySupport: boolean;
}

const PLAN_CONFIG: Record<Plan, PlanConfig> = {
  free: {
    monthlyScanLimit: 0,
    maxProjects: 1,
    teamMemberLimit: 1,
    canUseFixCenter: false,
    canUseCiGating: false,
    hasScanHistory: false,
    hasTrustBadge: false,
    canUseContinuousMonitoring: false,
    canUseLiveAlerts: false,
    canUseApi: false,
    hasPrioritySupport: false,
  },
  build: {
    monthlyScanLimit: 10,
    maxProjects: 3,
    teamMemberLimit: 3,
    canUseFixCenter: true,
    canUseCiGating: true,
    hasScanHistory: true,
    hasTrustBadge: true,
    canUseContinuousMonitoring: false,
    canUseLiveAlerts: false,
    canUseApi: false,
    hasPrioritySupport: false,
  },
  protect: {
    monthlyScanLimit: null,
    maxProjects: null,
    teamMemberLimit: 10,
    canUseFixCenter: true,
    canUseCiGating: true,
    hasScanHistory: true,
    hasTrustBadge: true,
    canUseContinuousMonitoring: true,
    canUseLiveAlerts: true,
    canUseApi: true,
    hasPrioritySupport: true,
  },
};

function config(plan: string | null | undefined): PlanConfig {
  return PLAN_CONFIG[normalizePlan(plan)];
}

/** Whether this plan can run a real scan at all. Separate from quota exhaustion — see billing/scanQuota.ts for "can run one more right now". */
export function canRunScan(plan: string | null | undefined): boolean {
  return config(plan).monthlyScanLimit !== 0;
}

/** null = unlimited/fair-use. 0 = the plan has no scan access at all (FREE). */
export function getMonthlyScanLimit(plan: string | null | undefined): number | null {
  return config(plan).monthlyScanLimit;
}

/** null = unlimited. */
export function getMaxProjects(plan: string | null | undefined): number | null {
  return config(plan).maxProjects;
}

export function canCreateProject(plan: string | null | undefined, currentCount: number): boolean {
  const max = getMaxProjects(plan);
  return max === null || currentCount < max;
}

export function canUseFixCenter(plan: string | null | undefined): boolean {
  return config(plan).canUseFixCenter;
}

export function canUseCiGating(plan: string | null | undefined): boolean {
  return config(plan).canUseCiGating;
}

export function hasScanHistory(plan: string | null | undefined): boolean {
  return config(plan).hasScanHistory;
}

export function hasTrustBadge(plan: string | null | undefined): boolean {
  return config(plan).hasTrustBadge;
}

export function canUseContinuousMonitoring(plan: string | null | undefined): boolean {
  return config(plan).canUseContinuousMonitoring;
}

export function canUseLiveAlerts(plan: string | null | undefined): boolean {
  return config(plan).canUseLiveAlerts;
}

export function canUseApi(plan: string | null | undefined): boolean {
  return config(plan).canUseApi;
}

export function getTeamMemberLimit(plan: string | null | undefined): number {
  return config(plan).teamMemberLimit;
}

export function hasPrioritySupport(plan: string | null | undefined): boolean {
  return config(plan).hasPrioritySupport;
}
