import { db, newId } from '../db/index';
import { incrementCounter, Metric } from '../observability/metrics';
import { ssrfSafeFetch, SsrfBlockedError } from '../scanner/ssrfSafeFetch';

export interface WebhookConfig {
  id: string;
  project_id: string;
  service: 'slack' | 'pagerduty' | 'splunk' | 'datadog' | 'generic';
  webhook_url: string;
  is_active: boolean;
  event_types: string[];
  created_at: string;
  updated_at: string;
}

export interface WebhookEvent {
  id: string;
  webhook_id: string;
  event_type: string;
  payload: Record<string, any>;
  status: 'pending' | 'sent' | 'failed' | 'retrying';
  attempt_count: number;
  last_error?: string;
  created_at: string;
  sent_at?: string;
}

// Store webhook configuration
export async function createWebhookConfig(
  projectId: string,
  service: string,
  webhookUrl: string,
  eventTypes: string[]
): Promise<WebhookConfig> {
  const id = newId();
  const now = new Date().toISOString();

  await db.prepare(`
    INSERT INTO webhooks
    (id, project_id, service, webhook_url, is_active, event_types, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    projectId,
    service,
    webhookUrl,
    1,
    JSON.stringify(eventTypes),
    now,
    now
  );

  return {
    id,
    project_id: projectId,
    service: service as any,
    webhook_url: webhookUrl,
    is_active: true,
    event_types: eventTypes,
    created_at: now,
    updated_at: now,
  };
}

// Get webhook configurations for project
export async function getWebhookConfigs(projectId: string, service?: string): Promise<WebhookConfig[]> {
  let query = 'SELECT * FROM webhooks WHERE project_id = ?';
  const params: any[] = [projectId];

  if (service) {
    query += ' AND service = ?';
    params.push(service);
  }

  const rows = (await db.prepare(query).all(...params)) as any[];
  return rows.map(row => ({
    id: row.id,
    project_id: row.project_id,
    service: row.service,
    webhook_url: row.webhook_url,
    is_active: row.is_active === 1,
    event_types: JSON.parse(row.event_types || '[]'),
    created_at: row.created_at,
    updated_at: row.updated_at,
  }));
}

// Queue event for webhook delivery
export async function queueWebhookEvent(
  webhookId: string,
  eventType: string,
  payload: Record<string, any>
): Promise<WebhookEvent> {
  const id = newId();
  const now = new Date().toISOString();

  await db.prepare(`
    INSERT INTO webhook_events
    (id, webhook_id, event_type, payload, status, attempt_count, created_at)
    VALUES (?, ?, ?, ?, 'pending', 0, ?)
  `).run(id, webhookId, eventType, JSON.stringify(payload), now);

  return {
    id,
    webhook_id: webhookId,
    event_type: eventType,
    payload,
    status: 'pending',
    attempt_count: 0,
    created_at: now,
  };
}

// Send webhook with retry logic. When `service` is provided, only webhooks
// configured for that service are considered — otherwise a service-shaped
// payload (e.g. Slack's attachment format) could be delivered to a webhook
// configured for a different service that happens to share an event type.
export async function sendWebhook(
  projectId: string,
  eventType: string,
  payload: Record<string, any>,
  service?: string
): Promise<void> {
  const webhooks = await getWebhookConfigs(projectId, service);

  for (const webhook of webhooks) {
    if (!webhook.is_active || !webhook.event_types.includes(eventType)) continue;

    const event = await queueWebhookEvent(webhook.id, eventType, payload);
    await deliverWebhook(webhook, event);
  }
}

async function deliverWebhook(webhook: WebhookConfig, event: WebhookEvent): Promise<void> {
  // A security/anomaly alert that's still undecided 11 minutes after it
  // fired isn't useful even as "fire and forget" background delivery, and
  // this is directly awaited in real caller code paths (e.g. sendWebhook
  // used inline by tests and by some integrations), so an unbounded-feeling
  // wait here becomes a caller-visible hang. 4 attempts over well under a
  // minute keeps meaningful retry resilience against a transient blip
  // without that cost.
  const maxRetries = 4;
  const backoffMs = [1000, 3000, 10000];

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      // Delivered through the same SSRF-hardened client the URL scanner
      // uses (resolves the hostname itself, validates every address
      // against the private/reserved-range blocklist, pins the connection
      // to the validated address, and re-validates every redirect hop) —
      // webhook_url is customer-supplied and this request is made from
      // Nettle's own infrastructure, exactly the SSRF shape ssrfSafeFetch
      // exists for. Its own 10s per-attempt timeout matches what this used
      // to configure manually via AbortController.
      const result = await ssrfSafeFetch(webhook.webhook_url, undefined, undefined, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Nettle-Signature': generateSignature(event.payload),
          'X-Nettle-Event-Type': event.event_type,
        },
        body: JSON.stringify({
          id: event.id,
          timestamp: event.created_at,
          event_type: event.event_type,
          data: event.payload,
        }),
      });

      if (result.statusCode >= 200 && result.statusCode < 300) {
        await updateWebhookEventStatus(event.id, 'sent');
        return;
      }

      // A 4xx (other than 429 rate-limiting) means the request itself is
      // wrong — a bad URL, an unauthorized endpoint, a malformed payload.
      // Retrying with backoff can't fix that; only 5xx/network failures and
      // 429 are transient enough to be worth retrying.
      const isPermanentFailure = result.statusCode >= 400 && result.statusCode < 500 && result.statusCode !== 429;

      if (!isPermanentFailure && attempt < maxRetries - 1) {
        await new Promise(resolve => setTimeout(resolve, backoffMs[attempt]));
        await db.prepare(`
          UPDATE webhook_events
          SET status = 'retrying', attempt_count = attempt_count + 1
          WHERE id = ?
        `).run(event.id);
      } else {
        await updateWebhookEventStatus(event.id, 'failed', `HTTP ${result.statusCode}`);
        return;
      }
    } catch (error) {
      // A webhook pointed at a private/reserved address, a blocked
      // hostname, or an unsupported scheme is never going to succeed on
      // retry — treat it as permanent so a malicious or misconfigured
      // destination doesn't get retried for a full minute.
      if (error instanceof SsrfBlockedError) {
        await updateWebhookEventStatus(event.id, 'failed', error.message);
        return;
      }

      const errMsg = error instanceof Error ? error.message : 'Unknown error';

      if (attempt < maxRetries - 1) {
        await new Promise(resolve => setTimeout(resolve, backoffMs[attempt]));
        await db.prepare(`
          UPDATE webhook_events
          SET status = 'retrying', attempt_count = attempt_count + 1
          WHERE id = ?
        `).run(event.id);
      } else {
        await updateWebhookEventStatus(event.id, 'failed', errMsg);
      }
    }
  }
}

async function updateWebhookEventStatus(
  eventId: string,
  status: string,
  error?: string
): Promise<void> {
  const now = new Date().toISOString();

  await db.prepare(`
    UPDATE webhook_events
    SET status = ?, sent_at = ?, last_error = ?
    WHERE id = ?
  `).run(status, status === 'sent' ? now : null, error || null, eventId);

  if (status === 'failed') incrementCounter(Metric.WebhookDeliveryFailures);
}

export class MissingWebhookSecretError extends Error {
  constructor() {
    super(
      "NETTLE_WEBHOOK_SECRET is not configured — outbound webhook payloads cannot be signed until it is. " +
        "Set an explicit value (e.g. via `openssl rand -hex 32`) in the environment; there is no default."
    );
  }
}

export function generateSignature(payload: Record<string, any>): string {
  const crypto = require('crypto');
  const secret = process.env.NETTLE_WEBHOOK_SECRET;
  if (!secret) throw new MissingWebhookSecretError();
  return crypto
    .createHmac('sha256', secret)
    .update(JSON.stringify(payload))
    .digest('hex');
}
