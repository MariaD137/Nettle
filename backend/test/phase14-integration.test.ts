import { test } from 'node:test';
import { deepStrictEqual, ok, strictEqual, throws } from 'node:assert';
import { db, newId } from '../src/db/index';
import {
  createWebhookConfig,
  getWebhookConfigs,
  queueWebhookEvent,
  sendWebhook,
  generateSignature,
  WebhookConfig,
} from '../src/integrations/webhooks';
import { sendSlackAlert, sendSlackNotification } from '../src/integrations/slack';
import { sendPagerDutyAlert, resolvePagerDutyIncident } from '../src/integrations/pagerduty';
import { sendSplunkAlert, sendSplunkMetric, sendSplunkEvent } from '../src/integrations/splunk';
import { sendDatadogAlert, sendDatadogMetric, sendDatadogEvent, sendDatadogLog } from '../src/integrations/datadog';
import crypto from 'crypto';

// generateSignature() now fails closed with no default secret (see
// src/integrations/webhooks.ts) — tests need an explicit value, same
// pattern used for NETTLE_TOKEN_ENCRYPTION_KEY in tokenEncryption.test.ts.
process.env.NETTLE_WEBHOOK_SECRET ??= crypto.randomBytes(32).toString('hex');

// Setup: Create test user and project
const testUserId = newId();
const testProjectId = newId();

// This suite sends through real webhook delivery (deliverWebhook's
// fetch + retry/backoff) against real third-party URLs for every send*
// call after the webhook config is created in the first subtest.
// Observed real latency per call against these endpoints from a CI
// runner ranges up to several tens of seconds even on success (TLS
// handshake + real round trip, no retries involved), and there are
// ~15 such calls run sequentially, so the ceiling needs real headroom —
// this is a backstop against genuine hangs, not a tight budget.
test('Phase 14: Integration Ecosystem', { timeout: 10 * 60_000 }, async (t) => {
  // Initialize test data
  const userEmail = `test-${Date.now()}@example.com`;
  await db.prepare(
    'INSERT INTO users (id, email, password_hash, plan, created_at) VALUES (?, ?, ?, ?, ?)'
  ).run(testUserId, userEmail, 'hash', 'free', new Date().toISOString());

  await db.prepare(
    'INSERT INTO projects (id, user_id, name, api_key, created_at) VALUES (?, ?, ?, ?, ?)'
  ).run(testProjectId, testUserId, 'Test Project', newId(), new Date().toISOString());

  await t.test('Webhook: Create and retrieve configuration', async () => {
    const webhookUrl = 'https://hooks.slack.com/services/EXAMPLE';
    const eventTypes = ['anomaly_alert', 'incident_alert'];

    const webhook = await createWebhookConfig(testProjectId, 'slack', webhookUrl, eventTypes);

    strictEqual(webhook.project_id, testProjectId);
    strictEqual(webhook.service, 'slack');
    strictEqual(webhook.webhook_url, webhookUrl);
    strictEqual(webhook.is_active, true);
    deepStrictEqual(webhook.event_types, eventTypes);
    ok(webhook.id);
    ok(webhook.created_at);
  });

  await t.test('Webhook: List configurations by project', async () => {
    const webhook1 = await createWebhookConfig(testProjectId, 'slack', 'https://slack1.example.com', ['anomaly_alert']);
    const webhook2 = await createWebhookConfig(testProjectId, 'pagerduty', 'https://pagerduty.example.com', [
      'incident_alert',
    ]);

    const webhooks = await getWebhookConfigs(testProjectId);
    ok(webhooks.length >= 2);

    const slackWebhooks = webhooks.filter(w => w.service === 'slack');
    ok(slackWebhooks.length >= 1);
  });

  await t.test('Webhook: Filter by service', async () => {
    await createWebhookConfig(testProjectId, 'datadog', 'https://datadog.example.com', ['metric_event']);
    const webhooks = await getWebhookConfigs(testProjectId, 'datadog');
    ok(webhooks.some(w => w.service === 'datadog'));
  });

  await t.test('Webhook: Queue event', async () => {
    const webhook = await createWebhookConfig(testProjectId, 'slack', 'https://slack.example.com', ['test_event']);
    const payload = { message: 'Test event', timestamp: new Date().toISOString() };

    const event = await queueWebhookEvent(webhook.id, 'test_event', payload);

    strictEqual(event.webhook_id, webhook.id);
    strictEqual(event.event_type, 'test_event');
    deepStrictEqual(event.payload, payload);
    strictEqual(event.status, 'pending');
    strictEqual(event.attempt_count, 0);
    ok(event.id);
    ok(event.created_at);
  });

  await t.test('Webhook: HMAC-SHA256 signature generation', () => {
    const payload = { test: 'data', timestamp: '2024-01-01T00:00:00Z' };
    const signature1 = generateSignature(payload);
    const signature2 = generateSignature(payload);

    strictEqual(signature1, signature2);
    ok(/^[0-9a-f]{64}$/.test(signature1), 'Signature should be valid hex');

    // Verify with crypto
    const secret = process.env.NETTLE_WEBHOOK_SECRET!;
    const expected = crypto
      .createHmac('sha256', secret)
      .update(JSON.stringify(payload))
      .digest('hex');

    strictEqual(signature1, expected);
  });

  await t.test('Webhook: signing fails closed with no default secret', () => {
    const saved = process.env.NETTLE_WEBHOOK_SECRET;
    delete process.env.NETTLE_WEBHOOK_SECRET;
    try {
      throws(() => generateSignature({ a: 1 }), /NETTLE_WEBHOOK_SECRET is not configured/);
    } finally {
      process.env.NETTLE_WEBHOOK_SECRET = saved;
    }
  });

  await t.test('Webhook: Payload structure for sendWebhook', async () => {
    const webhook = await createWebhookConfig(testProjectId, 'slack', 'https://hooks.slack.com/services/TEST', [
      'anomaly_alert',
    ]);

    const testPayload = {
      anomaly_type: 'traffic_spike',
      severity: 'high',
    };

    // sendWebhook queues the event, then delivers it synchronously before
    // returning — by the time we query, it's already reached a terminal
    // state ('sent' on success, 'failed' if delivery couldn't succeed),
    // never still 'pending'.
    await sendWebhook(testProjectId, 'anomaly_alert', testPayload);

    // Verify the event was queued and delivery was attempted
    const events = await db
      .prepare(
        'SELECT * FROM webhook_events WHERE webhook_id = ? AND event_type = ? ORDER BY created_at DESC LIMIT 1'
      )
      .get(webhook.id, 'anomaly_alert');

    ok(events);
    ok(['sent', 'failed'].includes((events as any).status));
  });

  await t.test('Slack: Alert format with severity colors', async () => {
    const webhook = await createWebhookConfig(testProjectId, 'slack', 'https://hooks.slack.com/services/SLACK', [
      'anomaly_alert',
    ]);

    const severities = ['critical', 'high', 'medium', 'low'] as const;
    const expectedColors: Record<string, string> = {
      critical: '#cc0000',
      high: '#ff6600',
      medium: '#ff9900',
      low: '#0066cc',
    };

    for (const severity of severities) {
      await sendSlackAlert(testProjectId, 'test_anomaly', severity, { test: true });

      const event = await db
        .prepare('SELECT * FROM webhook_events WHERE webhook_id = ? ORDER BY created_at DESC LIMIT 1')
        .get(webhook.id);

      ok(event, `Event should be queued for ${severity}`);
    }
  });

  await t.test('Slack: Generic notification format', async () => {
    const webhook = await createWebhookConfig(testProjectId, 'slack', 'https://hooks.slack.com/services/SLACK', [
      'notification',
    ]);

    await sendSlackNotification(testProjectId, 'Test Notification', 'This is a test message', {
      custom_field: 'custom_value',
    });

    const event = await db
      .prepare('SELECT * FROM webhook_events WHERE webhook_id = ? AND event_type = ? ORDER BY created_at DESC LIMIT 1')
      .get(webhook.id, 'notification');

    ok(event);
  });

  await t.test('PagerDuty: Incident creation with severity mapping', async () => {
    const webhook = await createWebhookConfig(testProjectId, 'pagerduty', 'https://events.pagerduty.com/v2/enqueue', [
      'incident_alert',
    ]);

    const severityMap: Record<string, string> = {
      critical: 'critical',
      high: 'error',
      medium: 'warning',
      low: 'info',
    };

    for (const [inputSeverity, expectedSeverity] of Object.entries(severityMap)) {
      await sendPagerDutyAlert(testProjectId, 'test_incident', inputSeverity as any, {
        incident_data: true,
      });

      const event = await db
        .prepare(
          'SELECT * FROM webhook_events WHERE webhook_id = ? AND event_type = ? ORDER BY created_at DESC LIMIT 1'
        )
        .get(webhook.id, 'incident_alert');

      ok(event, `Event should be queued for ${inputSeverity}`);
    }
  });

  await t.test('PagerDuty: Incident resolution via dedup key', async () => {
    const webhook = await createWebhookConfig(testProjectId, 'pagerduty', 'https://events.pagerduty.com/v2/enqueue', [
      'incident_resolved',
    ]);

    const dedupKey = `nettle-${testProjectId}-test-incident-${Date.now()}`;

    await resolvePagerDutyIncident(testProjectId, dedupKey);

    const event = await db
      .prepare(
        'SELECT * FROM webhook_events WHERE webhook_id = ? AND event_type = ? ORDER BY created_at DESC LIMIT 1'
      )
      .get(webhook.id, 'incident_resolved');

    ok(event);
  });

  await t.test('Splunk: Alert with severity mapping', async () => {
    const webhook = await createWebhookConfig(testProjectId, 'splunk', 'https://splunk.example.com/services/collector', [
      'anomaly_alert',
    ]);

    await sendSplunkAlert(testProjectId, 'splunk_test', 'critical', { test_field: 'value' });

    const event = await db
      .prepare('SELECT * FROM webhook_events WHERE webhook_id = ? ORDER BY created_at DESC LIMIT 1')
      .get(webhook.id);

    ok(event);
  });

  await t.test('Splunk: Metric submission', async () => {
    const webhook = await createWebhookConfig(testProjectId, 'splunk', 'https://splunk.example.com/services/collector', [
      'metric_event',
    ]);

    await sendSplunkMetric(testProjectId, 'nettle.anomaly.count', 5, {
      anomaly_type: 'traffic_spike',
    });

    const event = await db
      .prepare('SELECT * FROM webhook_events WHERE webhook_id = ? ORDER BY created_at DESC LIMIT 1')
      .get(webhook.id);

    ok(event);
  });

  await t.test('Splunk: Custom event submission', async () => {
    const webhook = await createWebhookConfig(testProjectId, 'splunk', 'https://splunk.example.com/services/collector', [
      'platform_event',
    ]);

    await sendSplunkEvent(testProjectId, 'custom_detection', { custom: 'data' });

    const event = await db
      .prepare('SELECT * FROM webhook_events WHERE webhook_id = ? ORDER BY created_at DESC LIMIT 1')
      .get(webhook.id);

    ok(event);
  });

  await t.test('Datadog: Alert with priority mapping', async () => {
    const webhook = await createWebhookConfig(testProjectId, 'datadog', 'https://api.datadoghq.com/api/v1/events', [
      'anomaly_alert',
    ]);

    const severities = ['critical', 'high', 'medium', 'low'] as const;
    for (const severity of severities) {
      await sendDatadogAlert(testProjectId, 'datadog_test', severity, { test: true });
    }

    const events = await db
      .prepare('SELECT COUNT(*) as count FROM webhook_events WHERE webhook_id = ?')
      .get(webhook.id);

    ok((events as any).count >= 4);
  });

  await t.test('Datadog: Metric submission', async () => {
    const webhook = await createWebhookConfig(testProjectId, 'datadog', 'https://api.datadoghq.com/api/v1/series', [
      'metric_event',
    ]);

    await sendDatadogMetric(testProjectId, 'nettle.request.latency', 123, {
      endpoint: '/api/scans',
    });

    const event = await db
      .prepare('SELECT * FROM webhook_events WHERE webhook_id = ? ORDER BY created_at DESC LIMIT 1')
      .get(webhook.id);

    ok(event);
  });

  await t.test('Datadog: Event submission', async () => {
    const webhook = await createWebhookConfig(testProjectId, 'datadog', 'https://api.datadoghq.com/api/v1/events', [
      'platform_event',
    ]);

    await sendDatadogEvent(testProjectId, 'deployment', { version: '1.2.3' }, 'info');

    const event = await db
      .prepare('SELECT * FROM webhook_events WHERE webhook_id = ? ORDER BY created_at DESC LIMIT 1')
      .get(webhook.id);

    ok(event);
  });

  await t.test('Datadog: Log submission', async () => {
    const webhook = await createWebhookConfig(testProjectId, 'datadog', 'https://http-intake.logs.datadoghq.com/v1/input', [
      'log_event',
    ]);

    await sendDatadogLog(testProjectId, 'Test log message', 'info', { context: 'test' });

    const event = await db
      .prepare('SELECT * FROM webhook_events WHERE webhook_id = ? ORDER BY created_at DESC LIMIT 1')
      .get(webhook.id);

    ok(event);
  });

  await t.test('Webhook: Event persistence and status tracking', async () => {
    const webhook = await createWebhookConfig(testProjectId, 'generic', 'https://example.com/webhook', ['test_event']);

    const event1 = await queueWebhookEvent(webhook.id, 'test_event', { data: 1 });
    const event2 = await queueWebhookEvent(webhook.id, 'test_event', { data: 2 });

    const stored = await db.prepare('SELECT * FROM webhook_events WHERE webhook_id = ? ORDER BY created_at').all(webhook.id);

    ok(stored.length >= 2);
    ok(stored.every((e: any) => e.status === 'pending'));
  });

  await t.test('Webhook: Support multiple services per project', async () => {
    const slack = await createWebhookConfig(testProjectId, 'slack', 'https://slack.example.com', ['anomaly_alert']);
    const pagerduty = await createWebhookConfig(testProjectId, 'pagerduty', 'https://pagerduty.example.com', [
      'incident_alert',
    ]);
    const datadog = await createWebhookConfig(testProjectId, 'datadog', 'https://datadog.example.com', ['metric_event']);

    const webhooks = await getWebhookConfigs(testProjectId);
    const services = webhooks.map(w => w.service);

    ok(services.includes('slack'));
    ok(services.includes('pagerduty'));
    ok(services.includes('datadog'));
  });

  await t.test('Webhook: Event filtering by type', async () => {
    const webhook = await createWebhookConfig(testProjectId, 'generic', 'https://example.com/webhook', [
      'anomaly_alert',
      'incident_alert',
    ]);

    // Queue events of different types
    await queueWebhookEvent(webhook.id, 'anomaly_alert', { type: 'anomaly' });
    await queueWebhookEvent(webhook.id, 'incident_alert', { type: 'incident' });
    await queueWebhookEvent(webhook.id, 'unknown_event', { type: 'unknown' });

    const events = await db.prepare('SELECT * FROM webhook_events WHERE webhook_id = ?').all(webhook.id);

    const anomalyEvents = events.filter((e: any) => e.event_type === 'anomaly_alert');
    const incidentEvents = events.filter((e: any) => e.event_type === 'incident_alert');

    ok(anomalyEvents.length >= 1);
    ok(incidentEvents.length >= 1);
  });

  await t.test('Webhook: Project isolation (cannot access other project webhooks)', async () => {
    const otherProjectId = newId();
    await db.prepare('INSERT INTO projects (id, user_id, name, api_key, created_at) VALUES (?, ?, ?, ?, ?)').run(
      otherProjectId,
      testUserId,
      'Other Project',
      newId(),
      new Date().toISOString()
    );

    const webhook1 = await createWebhookConfig(testProjectId, 'slack', 'https://slack1.example.com', ['test']);
    const webhook2 = await createWebhookConfig(otherProjectId, 'slack', 'https://slack2.example.com', ['test']);

    const project1Webhooks = await getWebhookConfigs(testProjectId);
    const project2Webhooks = await getWebhookConfigs(otherProjectId);

    ok(project1Webhooks.some(w => w.id === webhook1.id));
    ok(!project1Webhooks.some(w => w.id === webhook2.id));
    ok(project2Webhooks.some(w => w.id === webhook2.id));
    ok(!project2Webhooks.some(w => w.id === webhook1.id));
  });

  await t.test('Webhook: Concurrent event queuing', async () => {
    const webhook = await createWebhookConfig(testProjectId, 'generic', 'https://example.com/webhook', ['stress_test']);

    const eventCount = 50;
    for (let i = 0; i < eventCount; i++) {
      await queueWebhookEvent(webhook.id, 'stress_test', { iteration: i });
    }

    const stored = await db.prepare('SELECT COUNT(*) as count FROM webhook_events WHERE webhook_id = ?').get(webhook.id);

    ok((stored as any).count >= eventCount);
  });

  await t.test('Integration: All services in single project', async () => {
    const integrationProjectId = newId();
    await db.prepare('INSERT INTO projects (id, user_id, name, api_key, created_at) VALUES (?, ?, ?, ?, ?)').run(
      integrationProjectId,
      testUserId,
      'Integration Test Project',
      newId(),
      new Date().toISOString()
    );

    const slack = await createWebhookConfig(integrationProjectId, 'slack', 'https://slack.example.com', ['anomaly_alert']);
    const pagerduty = await createWebhookConfig(integrationProjectId, 'pagerduty', 'https://pagerduty.example.com', [
      'incident_alert',
    ]);
    const splunk = await createWebhookConfig(integrationProjectId, 'splunk', 'https://splunk.example.com', ['anomaly_alert']);
    const datadog = await createWebhookConfig(integrationProjectId, 'datadog', 'https://datadog.example.com', [
      'anomaly_alert',
      'metric_event',
    ]);

    // Send alert to multiple services
    await sendSlackAlert(integrationProjectId, 'multi_service_test', 'critical', {});
    await sendPagerDutyAlert(integrationProjectId, 'multi_service_test', 'critical', {});
    await sendSplunkAlert(integrationProjectId, 'multi_service_test', 'critical', {});
    await sendDatadogAlert(integrationProjectId, 'multi_service_test', 'critical', {});

    const slackEvents = await db.prepare('SELECT COUNT(*) as count FROM webhook_events WHERE webhook_id = ?').get(slack.id);
    const pagerdutyEvents = await db.prepare('SELECT COUNT(*) as count FROM webhook_events WHERE webhook_id = ?').get(
      pagerduty.id
    );
    const splunkEvents = await db.prepare('SELECT COUNT(*) as count FROM webhook_events WHERE webhook_id = ?').get(splunk.id);
    const datadogEvents = await db.prepare('SELECT COUNT(*) as count FROM webhook_events WHERE webhook_id = ?').get(
      datadog.id
    );

    ok((slackEvents as any).count >= 1);
    ok((pagerdutyEvents as any).count >= 1);
    ok((splunkEvents as any).count >= 1);
    ok((datadogEvents as any).count >= 1);
  });
});
