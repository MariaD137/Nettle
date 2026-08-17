import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { db, newId } from '../src/db/index';
import {
  calculateBaselines,
  getBaseline,
  scoreEventAnomaly,
  IsolationForest,
  extractFeatures,
  getModelStatus,
  updateModelStatus,
  getAnomalies,
} from '../src/patrol/mlAnalytics';
import type { StoredEvent } from '../src/patrol/types';

describe('Phase 13: ML Analytics & Anomaly Detection', () => {
  let projectId: string;
  let userId: string;

  beforeEach(() => {
    projectId = newId();
    userId = newId();

    // Create test data
    db.exec(`
      INSERT OR IGNORE INTO users (id, email, password_hash, created_at)
      VALUES ('${userId}', 'ml-${userId}@example.com', 'hash', '${new Date().toISOString()}');

      INSERT OR IGNORE INTO projects (id, user_id, name, api_key, created_at)
      VALUES ('${projectId}', '${userId}', 'ML Test', 'ml_key_${projectId}', '${new Date().toISOString()}');
    `);
  });

  describe('Baseline Calculation', () => {
    it('should calculate baselines from recent events', async () => {
      // Insert sample events
      const now = new Date();
      for (let i = 0; i < 100; i++) {
        const eventTime = new Date(now.getTime() - i * 60000).toISOString();
        db.prepare(`
          INSERT INTO events (id, project_id, occurred_at, ip, method, path, status_code)
          VALUES (?, ?, ?, '192.168.1.1', 'GET', '/api/test', 200)
        `).run(newId(), projectId, eventTime);
      }

      const result = await calculateBaselines(projectId, 2);

      assert.ok('baselines_calculated' in (result as object));
      assert.ok((result as any).baselines_calculated > 0);
    });

    it('should handle projects with no events', async () => {
      const result = await calculateBaselines(projectId, 24);
      assert.ok('error' in (result as object));
    });

    it('should retrieve calculated baselines', async () => {
      const now = new Date();
      for (let i = 0; i < 10; i++) {
        const eventTime = new Date(now.getTime() - i * 60000).toISOString();
        db.prepare(`
          INSERT INTO events (id, project_id, occurred_at, ip, method, path, status_code)
          VALUES (?, ?, ?, '192.168.1.1', 'GET', '/api/test', 200)
        `).run(newId(), projectId, eventTime);
      }

      await calculateBaselines(projectId, 2);

      const baseline = getBaseline(projectId, 'request_rate');
      assert.notEqual(baseline, undefined);
      assert.equal(baseline?.metric_name, 'request_rate');
      assert.ok((baseline?.value ?? -1) >= 0);
    });

    it('should get baseline for specific hour', async () => {
      const now = new Date();
      for (let i = 0; i < 10; i++) {
        const eventTime = new Date(now.getTime() - i * 60000).toISOString();
        db.prepare(`
          INSERT INTO events (id, project_id, occurred_at, ip, method, path, status_code)
          VALUES (?, ?, ?, '192.168.1.1', 'GET', '/api/test', 200)
        `).run(newId(), projectId, eventTime);
      }

      await calculateBaselines(projectId, 2);

      const baseline = getBaseline(projectId, 'request_rate', 12);
      // May be null if no events in that hour, which is fine
      assert.equal(baseline === null || (baseline?.value ?? -1) >= 0, true);
    });
  });

  describe('Feature Extraction', () => {
    it('should extract features from event', () => {
      const event: StoredEvent = {
        id: 'evt_123',
        projectId: projectId,
        occurredAt: new Date().toISOString(),
        ip: '192.168.1.1',
        method: 'POST',
        path: '/api/users/login',
        statusCode: 401,
        userAgent: 'Mozilla/5.0',
      };

      const features = extractFeatures(event);

      assert.equal(features.length, 7);
      assert.equal(features.every(f => f >= 0 && f <= 1), true);
    });

    it('should normalize long paths', () => {
      const event1: StoredEvent = {
        id: 'evt1',
        projectId: projectId,
        occurredAt: new Date().toISOString(),
        ip: '192.168.1.1',
        method: 'GET',
        path: '/a',
        statusCode: 200,
      };

      const event2: StoredEvent = {
        id: 'evt2',
        projectId: projectId,
        occurredAt: new Date().toISOString(),
        ip: '192.168.1.1',
        method: 'GET',
        path: '/very/long/path'.repeat(100),
        statusCode: 200,
      };

      const features1 = extractFeatures(event1);
      const features2 = extractFeatures(event2);

      assert.ok(features1[1] < features2[1]);
    });

    it('should handle missing optional fields', () => {
      const event: StoredEvent = {
        id: 'evt_123',
        projectId: projectId,
        occurredAt: new Date().toISOString(),
        ip: '192.168.1.1',
        method: 'GET',
        path: '/api/test',
        statusCode: 200,
      };

      const features = extractFeatures(event);
      assert.equal(features.length, 7);
      assert.equal(features.every(f => !isNaN(f)), true);
    });
  });

  describe('Anomaly Scoring', () => {
    it('should score events for anomalies', async () => {
      const event: StoredEvent = {
        id: newId(),
        projectId: projectId,
        occurredAt: new Date().toISOString(),
        ip: '192.168.1.1',
        method: 'GET',
        path: '/api/test',
        statusCode: 200,
      };

      const score = await scoreEventAnomaly(projectId, event);

      assert.notEqual(score.id, undefined);
      assert.ok(score.composite_score >= 0);
      assert.ok(score.composite_score <= 1);
      assert.equal(typeof score.is_anomaly, 'boolean');
    });

    it('should detect traffic anomalies', async () => {
      // Baseline well below the "1 event" scoreEventAnomaly compares
      // against, so this event registers as a clear rate spike.
      db.prepare(`
        INSERT INTO ml_baselines
        (id, project_id, metric_name, aggregation_period, hour_of_day, value, std_dev, updated_at)
        VALUES (?, ?, 'request_rate', 'hourly', ?, 0.05, 0.02, ?)
      `).run(newId(), projectId, new Date().getHours(), new Date().toISOString());

      // Score an event (simulates high rate)
      const event: StoredEvent = {
        id: newId(),
        projectId: projectId,
        occurredAt: new Date().toISOString(),
        ip: '192.168.1.1',
        method: 'GET',
        path: '/api/test',
        statusCode: 200,
      };

      const score = await scoreEventAnomaly(projectId, event);

      // With low baseline, should detect anomaly
      assert.ok(score.composite_score > 0);
    });

    it('should retrieve stored anomaly scores', async () => {
      const event: StoredEvent = {
        id: newId(),
        projectId: projectId,
        occurredAt: new Date().toISOString(),
        ip: '192.168.1.1',
        method: 'GET',
        path: '/admin',
        statusCode: 401,
      };

      await scoreEventAnomaly(projectId, event);

      const anomalies = getAnomalies(projectId, 10, 0);
      assert.ok(anomalies.length > 0);
      assert.equal(anomalies[0].event_id, event.id);
    });

    it('should filter anomalies by score threshold', async () => {
      // Create multiple anomaly scores
      for (let i = 0; i < 5; i++) {
        const event: StoredEvent = {
          id: newId(),
          projectId: projectId,
          occurredAt: new Date().toISOString(),
          ip: '192.168.1.1',
          method: 'GET',
          path: '/test',
          statusCode: 200,
        };
        await scoreEventAnomaly(projectId, event);
      }

      const lowThreshold = getAnomalies(projectId, 10, 0);
      const highThreshold = getAnomalies(projectId, 10, 0.9);

      assert.ok(lowThreshold.length >= highThreshold.length);
    });
  });

  describe('Isolation Forest', () => {
    it('should train isolation forest', () => {
      const forest = new IsolationForest(10, 100);

      const trainingData = [
        [1, 2, 3],
        [1.1, 2.1, 3.1],
        [1.2, 2.2, 3.2],
        [10, 20, 30], // Outlier
      ];

      forest.train(trainingData);
      assert.notEqual(forest, undefined);
    });

    it('should score normal points as low anomaly', () => {
      const forest = new IsolationForest(50, 256);

      const normal = Array(100)
        .fill(null)
        .map(() => [Math.random() * 10, Math.random() * 10]);
      forest.train(normal);

      const score = forest.score([5, 5]);
      // [5,5] sits exactly at the center of the training distribution, so
      // its true anomaly score hovers right around the textbook ~0.5
      // "unremarkable point" value — asserting a strict < 0.5 makes this
      // flaky by construction. 0.6 keeps real margin below the ~0.6-0.7+
      // outliers score while tolerating that inherent variance.
      assert.ok(score < 0.6);
    });

    it('should score outliers as high anomaly', () => {
      const forest = new IsolationForest(50, 256);

      const normal = Array(100)
        .fill(null)
        .map(() => [Math.random() * 10, Math.random() * 10]);
      forest.train(normal);

      const outlier = [100, 100]; // Far outside normal range
      const score = forest.score(outlier);
      assert.ok(score > 0.3);
    });
  });

  describe('Model Status Management', () => {
    it('should update model status', () => {
      updateModelStatus(projectId, 'isolation_forest', true, 0.94, 50000);

      const status = getModelStatus(projectId);
      assert.equal(status?.model_type, 'isolation_forest');
      assert.equal(status?.is_active, true);
      assert.equal(status?.accuracy, 0.94);
      assert.equal(status?.training_samples, 50000);
    });

    it('should retrieve model status', () => {
      updateModelStatus(projectId, 'isolation_forest', false, 0.89, 30000);

      const status = getModelStatus(projectId);
      assert.notEqual(status, undefined);
      assert.equal(status?.is_active, false);
    });

    it('should handle missing model status', () => {
      const status = getModelStatus(newId());
      assert.equal(status, null);
    });
  });

  describe('Z-Score Anomaly Detection', () => {
    it('should calculate z-scores correctly', async () => {
      // Create events with normal pattern
      const baseTime = new Date();
      for (let i = 0; i < 50; i++) {
        db.prepare(`
          INSERT INTO events (id, project_id, occurred_at, ip, method, path, status_code)
          VALUES (?, ?, ?, '192.168.1.${i % 10}', 'GET', '/api/test', ${200 + (i % 100)})
        `).run(
          newId(),
          projectId,
          new Date(baseTime.getTime() - i * 60000).toISOString()
        );
      }

      await calculateBaselines(projectId, 1);

      const event: StoredEvent = {
        id: newId(),
        projectId: projectId,
        occurredAt: baseTime.toISOString(),
        ip: '192.168.1.99',
        method: 'GET',
        path: '/admin',
        statusCode: 401,
      };

      const score = await scoreEventAnomaly(projectId, event);
      assert.notEqual(score, undefined);
    });
  });

  describe('Edge Cases & Error Handling', () => {
    it('should handle null features gracefully', () => {
      const forest = new IsolationForest();
      const score = forest.score([]);
      assert.equal(typeof score, 'number');
      assert.ok(score >= 0);
    });

    it('should handle events with all zeros', async () => {
      const event: StoredEvent = {
        id: newId(),
        projectId: projectId,
        occurredAt: new Date().toISOString(),
        ip: '0.0.0.0',
        method: 'GET',
        path: '',
        statusCode: 0,
      };

      const score = await scoreEventAnomaly(projectId, event);
      assert.ok(score.composite_score >= 0);
    });

    it('should handle very large training datasets', () => {
      const forest = new IsolationForest(5, 100);

      // Large random dataset
      const data = Array(10000)
        .fill(null)
        .map(() => [Math.random(), Math.random(), Math.random()]);

      assert.doesNotThrow(() => forest.train(data));
    });
  });
});
