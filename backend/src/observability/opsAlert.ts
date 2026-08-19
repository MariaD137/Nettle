import { sendEmail } from "../integrations/email";
import { ssrfSafeFetch, type SafeFetchResult } from "../scanner/ssrfSafeFetch";
import { log } from "./logger";

/**
 * Nettle's own operational alerting — distinct from the customer-facing
 * Patrol alert channels (integrations/{slack,pagerduty,datadog,splunk}.ts),
 * which notify a *customer's* team about issues in *that customer's*
 * monitored application. This module notifies Nettle's own operator about
 * issues in Nettle's own backend.
 *
 * Deliberately small and reuses what already exists rather than adding a
 * new monitoring system: a generic outbound webhook (works with Slack's
 * incoming-webhook format, PagerDuty Events, or any other receiver that
 * accepts a JSON POST — same shape the customer-facing webhooks already
 * use) and/or the existing SMTP email integration. Both are entirely
 * optional and configured only via environment variables:
 *
 *   NETTLE_OPS_ALERT_WEBHOOK_URL — POSTed a JSON payload on each alert.
 *   NETTLE_OPS_ALERT_EMAIL       — sent a plain-text email on each alert.
 *
 * Neither is hardcoded, and if neither is set this is an honest no-op
 * (opsAlertingConfigured() is false) — see README's REQUIRES AWS
 * CONFIGURATION note for what completes this in a real deployment
 * (CloudWatch Alarms / EventBridge notifications on top of App Runner's own
 * restart-count and health-check signal, which nothing at the application
 * level can see or substitute for).
 */

const WEBHOOK_URL = () => process.env.NETTLE_OPS_ALERT_WEBHOOK_URL || "";
const ALERT_EMAIL = () => process.env.NETTLE_OPS_ALERT_EMAIL || "";

export function opsAlertingConfigured(): boolean {
  return Boolean(WEBHOOK_URL() || ALERT_EMAIL());
}

export type OpsAlertCategory =
  | "unhandled_exception"
  | "unhandled_rejection"
  | "startup_failure"
  | "stripe_webhook_failures";

export interface OpsAlertInput {
  category: OpsAlertCategory;
  message: string;
  detail?: string;
}

/**
 * Best-effort and never throws — an ops-alerting outage (bad webhook URL,
 * SMTP down) must never become a second incident on top of whatever this
 * is trying to report, and must never block or crash the caller.
 *
 * `webhookFetcher` defaults to the real SSRF-hardened client (same pattern
 * urlSecurity.ts uses for its own fetcher param) and exists so tests can
 * inject a stub — NETTLE_OPS_ALERT_WEBHOOK_URL is meant to point at a real
 * external receiver (Slack, PagerDuty), which ssrfSafeFetch correctly
 * refuses to substitute a local test server for.
 */
export async function sendOpsAlert(
  alert: OpsAlertInput,
  webhookFetcher: (url: string, opts: { method: string; headers: Record<string, string>; body: string }) => Promise<SafeFetchResult> =
    (url, opts) => ssrfSafeFetch(url, undefined, undefined, opts)
): Promise<void> {
  if (!opsAlertingConfigured()) return;

  const text = `Nettle ops alert [${alert.category}]: ${alert.message}${alert.detail ? `\n\n${alert.detail}` : ""}`;
  const tasks: Promise<unknown>[] = [];

  const webhookUrl = WEBHOOK_URL();
  if (webhookUrl) {
    tasks.push(
      // Routed through the same SSRF-hardened client used everywhere else
      // an outbound request goes to a URL that lives in configuration
      // rather than a compile-time constant.
      webhookFetcher(webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text,
          category: alert.category,
          message: alert.message,
          detail: alert.detail ?? null,
        }),
      }).catch((err) => {
        log("error", "ops_alert_webhook_delivery_failed", { error: (err as Error).message, category: alert.category });
      })
    );
  }

  const alertEmail = ALERT_EMAIL();
  if (alertEmail) {
    tasks.push(
      sendEmail(alertEmail, `Nettle ops alert: ${alert.category}`, text).then((result) => {
        if (!result.sent) {
          log("error", "ops_alert_email_delivery_failed", { error: result.error, category: alert.category });
        }
      })
    );
  }

  await Promise.allSettled(tasks);
}

// --- Threshold + cooldown for high-volume categories ---------------------
//
// An unhandled exception or a fatal startup failure is inherently notable
// on its own (threshold 1, fire immediately) — see callers below. Stripe
// webhook failures are not: this endpoint is a public URL that bots and
// scanners hit constantly with garbage signatures, so alerting on every
// single 400 would be pure noise. recordOpsFailure() tracks an in-memory
// rolling count per category and only fires once the count crosses a
// threshold within a window, then stays quiet on that category for a
// cooldown period so a sustained failure pages once, not once per request.
//
// This state is in-process and resets on restart — it cannot detect a
// crash loop across restarts (there is no process alive in between to hold
// the counter). That specific gap is real infrastructure work, not
// something to fake here — see README's REQUIRES AWS CONFIGURATION note.

interface FailureWindow {
  count: number;
  windowStart: number;
  lastAlertAt: number;
}

const failureWindows = new Map<OpsAlertCategory, FailureWindow>();
const WINDOW_MS = 5 * 60 * 1000;
const COOLDOWN_MS = 15 * 60 * 1000;

export function recordOpsFailure(
  category: OpsAlertCategory,
  message: string,
  detail?: string,
  threshold = 5,
  alertFn: (alert: OpsAlertInput) => Promise<void> = sendOpsAlert
): void {
  const now = Date.now();
  let w = failureWindows.get(category);
  if (!w || now - w.windowStart > WINDOW_MS) {
    w = { count: 0, windowStart: now, lastAlertAt: w?.lastAlertAt ?? 0 };
    failureWindows.set(category, w);
  }
  w.count += 1;

  if (w.count >= threshold && now - w.lastAlertAt > COOLDOWN_MS) {
    w.lastAlertAt = now;
    void alertFn({
      category,
      message: `${message} (${w.count} in the last ${Math.round(WINDOW_MS / 60000)} minutes)`,
      detail,
    });
  }
}

// Test-only: lets tests reset rolling-window state between runs without
// waiting out WINDOW_MS/COOLDOWN_MS in real time.
export function _resetOpsFailureWindowsForTests(): void {
  failureWindows.clear();
}
