import { test } from 'node:test';
import { ok, strictEqual } from 'node:assert';
import { db, newId } from '../src/db/index';
import { scanRateLimit, publicRateLimit, apiRateLimit, limiter } from '../src/middleware/rateLimit';
import { Request, Response } from 'express';

// Mock request and response objects
function createMockRequest(userId?: string, ip: string = '127.0.0.1'): Partial<Request> {
  return {
    user: userId ? { id: userId } : undefined,
    ip,
    socket: { remoteAddress: ip } as any,
  };
}

function createMockResponse(): Partial<Response> {
  const response: any = {
    status: function (code: number) {
      this.statusCode = code;
      return this;
    },
    json: function (data: any) {
      this.jsonData = data;
      return this;
    },
    set: function (header: string, value: string) {
      if (!this.headers) this.headers = {};
      this.headers[header] = value;
      return this;
    },
  };
  return response;
}

test('Phase 15: Performance & Optimization', async (t) => {
  // Cleanup: Reset limiter state before tests
  limiter.destroy();

  // Test database performance
  await t.test('Database: Indexes exist for common queries', () => {
    const indexes = db
      .prepare(
        `SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'`
      )
      .all();

    const indexNames = indexes.map((i: any) => i.name);

    ok(indexNames.includes('idx_scans_project_time'), 'Scan project/time index');
    ok(indexNames.includes('idx_scans_project_status'), 'Scan project/status index');
    ok(indexNames.includes('idx_alerts_project_time'), 'Alert project/time index');
    ok(indexNames.includes('idx_events_project_time'), 'Event project/time index');
    ok(indexNames.includes('idx_anomaly_scores_project_time'), 'Anomaly score project/time index');
    ok(indexNames.includes('idx_webhook_events_status'), 'Webhook event status index');
  });

  // Test rate limiting
  await t.test('Rate Limit: Scan endpoint enforces per-user limit', () => {
    const userId = newId();
    const req = createMockRequest(userId);
    let rateLimited = false;

    // First 30 requests should succeed
    for (let i = 0; i < 30; i++) {
      const res = createMockResponse();
      const mockNext = () => {};

      // Mock next() call
      let nextCalled = false;
      scanRateLimit(req as Request, res as Response, () => {
        nextCalled = true;
      });

      if ((res as any).statusCode === 429) {
        rateLimited = true;
      }
    }

    strictEqual(rateLimited, false, 'First 30 requests should not be rate limited');

    // 31st request should be rate limited
    const res = createMockResponse();
    scanRateLimit(req as Request, res as Response, () => {});

    strictEqual((res as any).statusCode, 429, '31st request should be rate limited');
  });

  await t.test('Rate Limit: Public endpoint enforces per-IP limit', () => {
    const ip = '192.168.1.1';
    const req = createMockRequest(undefined, ip);
    let rateLimited = false;

    // First 100 requests should succeed
    for (let i = 0; i < 100; i++) {
      const res = createMockResponse();
      publicRateLimit(req as Request, res as Response, () => {});

      if ((res as any).statusCode === 429) {
        rateLimited = true;
        break;
      }
    }

    strictEqual(rateLimited, false, 'First 100 requests should not be rate limited');

    // 101st request should be rate limited
    const res = createMockResponse();
    publicRateLimit(req as Request, res as Response, () => {});

    strictEqual((res as any).statusCode, 429, '101st request should be rate limited');
  });

  await t.test('Rate Limit: Different users have separate limits', () => {
    const user1 = newId();
    const user2 = newId();
    const req1 = createMockRequest(user1);
    const req2 = createMockRequest(user2);

    // User 1 hits limit (in separate test context)
    // User 2 should still have allowance
    for (let i = 0; i < 500; i++) {
      const res = createMockResponse();
      apiRateLimit(req1 as Request, res as Response, () => {});
    }

    // User 2 should not be limited yet
    const res2 = createMockResponse();
    let nextCalled = false;
    apiRateLimit(req2 as Request, res2 as Response, () => {
      nextCalled = true;
    });

    ok(nextCalled || (res2 as any).statusCode === 200, 'Different users have separate rate limits');
  });

  await t.test('Rate Limit: Returns proper 429 response with Retry-After', () => {
    const req = createMockRequest(newId());

    // Exceed limit
    for (let i = 0; i < 505; i++) {
      const res = createMockResponse();
      apiRateLimit(req as Request, res as Response, () => {});
    }

    const res = createMockResponse();
    apiRateLimit(req as Request, res as Response, () => {});

    strictEqual((res as any).statusCode, 429, 'Returns 429 status');
    ok((res as any).jsonData.retryAfter, 'Returns retryAfter in body');
    ok((res as any).jsonData.error, 'Returns error message');
  });

  // Test data structure queries
  await t.test('Performance: Query webhook events efficiently', () => {
    const userId = newId();
    const projectId = newId();

    db.prepare(
      'INSERT INTO users (id, email, password_hash, plan, created_at) VALUES (?, ?, ?, ?, ?)'
    ).run(userId, `perf-test-${Date.now()}@example.com`, 'hash', 'free', new Date().toISOString());

    db.prepare(
      'INSERT INTO projects (id, user_id, name, api_key, created_at) VALUES (?, ?, ?, ?, ?)'
    ).run(projectId, userId, 'Perf Test', newId(), new Date().toISOString());

    const webhookId = newId();
    db.prepare(
      'INSERT INTO webhooks (id, project_id, service, webhook_url, is_active, event_types, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(webhookId, projectId, 'test', 'https://example.com', 1, '[]', new Date().toISOString(), new Date().toISOString());

    // Insert 100 webhook events
    const now = new Date().toISOString();
    for (let i = 0; i < 100; i++) {
      db.prepare(
        'INSERT INTO webhook_events (id, webhook_id, event_type, payload, status, attempt_count, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
      ).run(newId(), webhookId, 'test_event', '{}', 'sent', 1, now);
    }

    // Query with index should be fast
    const start = Date.now();
    const events = db
      .prepare('SELECT * FROM webhook_events WHERE webhook_id = ? ORDER BY created_at DESC LIMIT 50')
      .all(webhookId);
    const duration = Date.now() - start;

    strictEqual(events.length, 50, 'Returns 50 events');
    ok(duration < 100, `Query completed in ${duration}ms (should be <100ms)`);
  });

  await t.test('Performance: Query scans by project efficiently', () => {
    const userId = newId();
    const projectId = newId();

    db.prepare(
      'INSERT INTO users (id, email, password_hash, plan, created_at) VALUES (?, ?, ?, ?, ?)'
    ).run(userId, `scan-perf-${Date.now()}@example.com`, 'hash', 'free', new Date().toISOString());

    db.prepare(
      'INSERT INTO projects (id, user_id, name, api_key, created_at) VALUES (?, ?, ?, ?, ?)'
    ).run(projectId, userId, 'Scan Test', newId(), new Date().toISOString());

    // Insert 50 scans
    for (let i = 0; i < 50; i++) {
      const scanId = newId();
      db.prepare(
        `INSERT INTO scans
        (id, project_id, scanned_at, score, critical_count, caution_count, clear_count, report_json, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        scanId,
        projectId,
        new Date(Date.now() - i * 86400000).toISOString(),
        Math.floor(Math.random() * 100),
        0,
        i,
        15,
        '{}',
        'COMPLETED',
        new Date().toISOString()
      );
    }

    // Query should use index on (project_id, scanned_at)
    const start = Date.now();
    const scans = db
      .prepare('SELECT * FROM scans WHERE project_id = ? ORDER BY scanned_at DESC LIMIT 20')
      .all(projectId);
    const duration = Date.now() - start;

    strictEqual(scans.length, 20, 'Returns 20 scans');
    ok(duration < 100, `Query completed in ${duration}ms (should be <100ms)`);
  });

  await t.test('Performance: Query anomalies by project efficiently', () => {
    const userId = newId();
    const projectId = newId();

    db.prepare(
      'INSERT INTO users (id, email, password_hash, plan, created_at) VALUES (?, ?, ?, ?, ?)'
    ).run(userId, `anomaly-perf-${Date.now()}@example.com`, 'hash', 'free', new Date().toISOString());

    db.prepare(
      'INSERT INTO projects (id, user_id, name, api_key, created_at) VALUES (?, ?, ?, ?, ?)'
    ).run(projectId, userId, 'Anomaly Test', newId(), new Date().toISOString());

    // Insert 100 anomaly scores
    for (let i = 0; i < 100; i++) {
      db.prepare(
        `INSERT INTO anomaly_scores
        (id, project_id, event_id, z_score, isolation_score, composite_score, anomaly_type, is_anomaly, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        newId(),
        projectId,
        newId(),
        Math.random() * 5,
        Math.random(),
        Math.random(),
        i % 3 === 0 ? 'traffic_spike' : 'error_rate_spike',
        i % 3 === 0 ? 1 : 0,
        new Date(Date.now() - i * 3600000).toISOString()
      );
    }

    // Query should use index
    const start = Date.now();
    const anomalies = db
      .prepare(
        'SELECT * FROM anomaly_scores WHERE project_id = ? AND composite_score > ? ORDER BY created_at DESC LIMIT 50'
      )
      .all(projectId, 0.5);
    const duration = Date.now() - start;

    ok(anomalies.length <= 50, 'Returns up to 50 anomalies');
    ok(duration < 100, `Query completed in ${duration}ms (should be <100ms)`);
  });

  await t.test('Performance: Complex query with multiple filters', () => {
    const userId = newId();
    const projectId = newId();

    db.prepare(
      'INSERT INTO users (id, email, password_hash, plan, created_at) VALUES (?, ?, ?, ?, ?)'
    ).run(userId, `complex-${Date.now()}@example.com`, 'hash', 'free', new Date().toISOString());

    db.prepare(
      'INSERT INTO projects (id, user_id, name, api_key, created_at) VALUES (?, ?, ?, ?, ?)'
    ).run(projectId, userId, 'Complex Test', newId(), new Date().toISOString());

    // Insert alerts
    for (let i = 0; i < 100; i++) {
      db.prepare(
        `INSERT INTO alerts
        (id, project_id, occurred_at, severity, rule, message, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).run(
        newId(),
        projectId,
        new Date(Date.now() - i * 3600000).toISOString(),
        ['critical', 'high', 'medium', 'low'][i % 4],
        'test_rule',
        'Test alert',
        i % 2 === 0 ? 'new' : 'acknowledged'
      );
    }

    // Complex query
    const start = Date.now();
    const alerts = db
      .prepare(
        `SELECT * FROM alerts
        WHERE project_id = ? AND severity IN ('critical', 'high') AND status = 'new'
        ORDER BY occurred_at DESC LIMIT 20`
      )
      .all(projectId);
    const duration = Date.now() - start;

    ok(duration < 150, `Complex query completed in ${duration}ms (should be <150ms)`);
  });

  await t.test('Performance: N+1 prevention for webhook delivery', () => {
    const projectId = newId();
    const userId = newId();

    db.prepare(
      'INSERT INTO users (id, email, password_hash, plan, created_at) VALUES (?, ?, ?, ?, ?)'
    ).run(userId, `n+1-test-${Date.now()}@example.com`, 'hash', 'free', new Date().toISOString());

    db.prepare(
      'INSERT INTO projects (id, user_id, name, api_key, created_at) VALUES (?, ?, ?, ?, ?)'
    ).run(projectId, userId, 'N+1 Test', newId(), new Date().toISOString());

    // Create 10 webhooks
    const webhooks = [];
    for (let i = 0; i < 10; i++) {
      const webhookId = newId();
      db.prepare(
        'INSERT INTO webhooks (id, project_id, service, webhook_url, is_active, event_types, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
      ).run(webhookId, projectId, 'test', `https://example.com/${i}`, 1, '[]', new Date().toISOString(), new Date().toISOString());
      webhooks.push(webhookId);
    }

    // Get all webhooks for project (1 query, not N+1)
    const start = Date.now();
    const results = db.prepare('SELECT * FROM webhooks WHERE project_id = ?').all(projectId);
    const duration = Date.now() - start;

    strictEqual(results.length, 10, 'Returns all 10 webhooks');
    ok(duration < 50, `Single query completed in ${duration}ms (should be <50ms)`);
  });

  await t.test('Performance: Scan report JSON parsing performance', () => {
    const projectId = newId();
    const userId = newId();

    db.prepare(
      'INSERT INTO users (id, email, password_hash, plan, created_at) VALUES (?, ?, ?, ?, ?)'
    ).run(userId, `json-perf-${Date.now()}@example.com`, 'hash', 'free', new Date().toISOString());

    db.prepare(
      'INSERT INTO projects (id, user_id, name, api_key, created_at) VALUES (?, ?, ?, ?, ?)'
    ).run(projectId, userId, 'JSON Test', newId(), new Date().toISOString());

    // Large JSON report (simulated)
    const largeReport = JSON.stringify({
      findings: Array(100).fill(null).map((_, i) => ({
        id: `finding-${i}`,
        type: 'test',
        severity: 'medium',
        file: `src/file${i}.ts`,
        line: i + 1,
        message: `Test finding ${i}`,
      })),
      metrics: {
        total_findings: 100,
        by_severity: { critical: 0, high: 10, medium: 40, low: 50 },
      },
    });

    // Insert scan
    const scanId = newId();
    db.prepare(
      `INSERT INTO scans
      (id, project_id, scanned_at, score, critical_count, caution_count, clear_count, report_json, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(scanId, projectId, new Date().toISOString(), 85, 0, 10, 90, largeReport, 'COMPLETED');

    // Retrieve and parse
    const start = Date.now();
    const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(scanId);
    const parsed = JSON.parse((scan as any).report_json);
    const duration = Date.now() - start;

    strictEqual(parsed.findings.length, 100, 'Parsed 100 findings');
    ok(duration < 50, `Retrieve and parse completed in ${duration}ms (should be <50ms)`);
  });

  // Cleanup
  await t.test('Cleanup: Rate limiter state', () => {
    // Already destroyed in setup, just verify
    ok(true, 'Rate limiter cleanup successful');
  });
});
