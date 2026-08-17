import { db, newId } from '../db/index';

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
export function createWebhookConfig(
  projectId: string,
  service: string,
  webhookUrl: string,
  eventTypes: string[]
): WebhookConfig {
  const id = newId();
  const now = new Date().toISOString();

  db.prepare(`
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
export function getWebhookConfigs(projectId: string, service?: string): WebhookConfig[] {
  let query = 'SELECT * FROM webhooks WHERE project_id = ?';
  const params: any[] = [projectId];

  if (service) {
    query += ' AND service = ?';
    params.push(service);
  }

  const rows = db.prepare(query).all(...params) as any[];
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
export function queueWebhookEvent(
  webhookId: string,
  eventType: string,
  payload: Record<string, any>
): WebhookEvent {
  const id = newId();
  const now = new Date().toISOString();

  db.prepare(`
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
  const webhooks = getWebhookConfigs(projectId, service);

  for (const webhook of webhooks) {
    if (!webhook.is_active || !webhook.event_types.includes(eventType)) continue;

    const event = queueWebhookEvent(webhook.id, eventType, payload);
    await deliverWebhook(webhook, event);
  }
}

async function deliverWebhook(webhook: WebhookConfig, event: WebhookEvent): Promise<void> {
  const maxRetries = 5;
  const backoffMs = [1000, 5000, 30000, 2 * 60000, 8 * 60000];

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const response = await fetch(webhook.webhook_url, {
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

      if (response.ok) {
        updateWebhookEventStatus(event.id, 'sent');
        return;
      }

      if (attempt < maxRetries - 1) {
        await new Promise(resolve => setTimeout(resolve, backoffMs[attempt]));
        db.prepare(`
          UPDATE webhook_events
          SET status = 'retrying', attempt_count = attempt_count + 1
          WHERE id = ?
        `).run(event.id);
      } else {
        updateWebhookEventStatus(event.id, 'failed', `HTTP ${response.status}`);
      }
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : 'Unknown error';

      if (attempt < maxRetries - 1) {
        await new Promise(resolve => setTimeout(resolve, backoffMs[attempt]));
        db.prepare(`
          UPDATE webhook_events
          SET status = 'retrying', attempt_count = attempt_count + 1
          WHERE id = ?
        `).run(event.id);
      } else {
        updateWebhookEventStatus(event.id, 'failed', errMsg);
      }
    }
  }
}

function updateWebhookEventStatus(
  eventId: string,
  status: string,
  error?: string
): void {
  const now = new Date().toISOString();

  db.prepare(`
    UPDATE webhook_events
    SET status = ?, sent_at = ?, last_error = ?
    WHERE id = ?
  `).run(status, status === 'sent' ? now : null, error || null, eventId);
}

function generateSignature(payload: Record<string, any>): string {
  const crypto = require('crypto');
  const secret = process.env.NETTLE_WEBHOOK_SECRET || 'nettle-webhook';
  return crypto
    .createHmac('sha256', secret)
    .update(JSON.stringify(payload))
    .digest('hex');
}
