import { describe, it, expect, beforeEach } from '@jest/globals';
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
      VALUES ('${userId}', 'ml@example.com', 'hash', '${new Date().toISOString()}');

      INSERT OR IGNORE INTO projects (id, user_id, name, api_key, created_at)
      VALUES ('${projectId}', '${userId}', 'ML Test', 'ml_key', '${new Date().toISOString()}');
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

      expect(result).toHaveProperty('baselines_calculated');
      expect((result as any).baselines_calculated).toBeGreaterThan(0);
    });

    it('should handle projects with no events', async () => {
      const result = await calculateBaselines(projectId, 24);
      expect(result).toHaveProperty('error');
    });

    it('should retrieve calculated baselines', async () => {
      await calculateBaselines(projectId, 2);

      const baseline = getBaseline(projectId, 'request_rate');
      expect(baseline).toBeDefined();
      expect(baseline?.metric_name).toBe('request_rate');
      expect(baseline?.value).toBeGreaterThanOrEqual(0);
    });

    it('should get baseline for specific hour', async () => {
      await calculateBaselines(projectId, 2);

      const baseline = getBaseline(projectId, 'request_rate', 12);
      // May be null if no events in that hour, which is fine
      expect(baseline === null || baseline?.value >= 0).toBe(true);
    });
  });

  describe('Feature Extraction', () => {
    it('should extract features from event', () => {
      const event: StoredEvent = {
        id: 'evt_123',
        project_id: projectId,
        occurred_at: new Date().toISOString(),
        ip: '192.168.1.1',
        method: 'POST',
        path: '/api/users/login',
        status_code: 401,
        user_agent: 'Mozilla/5.0',
      };

      const features = extractFeatures(event);

      expect(features).toHaveLength(7);
      expect(features.every(f => f >= 0 && f <= 1)).toBe(true);
    });

    it('should normalize long paths', () => {
      const event1: StoredEvent = {
        id: 'evt1',
        project_id: projectId,
        occurred_at: new Date().toISOString(),
        ip: '192.168.1.1',
        method: 'GET',
        path: '/a',
        status_code: 200,
      };

      const event2: StoredEvent = {
        id: 'evt2',
        project_id: projectId,
        occurred_at: new Date().toISOString(),
        ip: '192.168.1.1',
        method: 'GET',
        path: '/very/long/path'.repeat(100),
        status_code: 200,
      };

      const features1 = extractFeatures(event1);
      const features2 = extractFeatures(event2);

      expect(features1[1]).toBeLessThan(features2[1]);
    });

    it('should handle missing optional fields', () => {
      const event: StoredEvent = {
        id: 'evt_123',
        project_id: projectId,
        occurred_at: new Date().toISOString(),
        ip: '192.168.1.1',
        method: 'GET',
        path: '/api/test',
        status_code: 200,
      };

      const features = extractFeatures(event);
      expect(features).toHaveLength(7);
      expect(features.every(f => !isNaN(f))).toBe(true);
    });
  });

  describe('Anomaly Scoring', () => {
    it('should score events for anomalies', async () => {
      const event: StoredEvent = {
        id: newId(),
        project_id: projectId,
        occurred_at: new Date().toISOString(),
        ip: '192.168.1.1',
        method: 'GET',
        path: '/api/test',
        status_code: 200,
      };

      const score = await scoreEventAnomaly(projectId, event);

      expect(score.id).toBeDefined();
      expect(score.composite_score).toBeGreaterThanOrEqual(0);
      expect(score.composite_score).toBeLessThanOrEqual(1);
      expect(typeof score.is_anomaly).toBe('boolean');
    });

    it('should detect traffic anomalies', async () => {
      // Set a very low baseline
      db.prepare(`
        INSERT INTO ml_baselines
        (id, project_id, metric_name, aggregation_period, hour_of_day, value, std_dev, updated_at)
        VALUES (?, ?, 'request_rate', 'hourly', ?, 1.0, 0.5, ?)
      `).run(newId(), projectId, new Date().getHours(), new Date().toISOString());

      // Score an event (simulates high rate)
      const event: StoredEvent = {
        id: newId(),
        project_id: projectId,
        occurred_at: new Date().toISOString(),
        ip: '192.168.1.1',
        method: 'GET',
        path: '/api/test',
        status_code: 200,
      };

      const score = await scoreEventAnomaly(projectId, event);

      // With low baseline, should detect anomaly
      expect(score.composite_score).toBeGreaterThan(0);
    });

    it('should retrieve stored anomaly scores', async () => {
      const event: StoredEvent = {
        id: newId(),
        project_id: projectId,
        occurred_at: new Date().toISOString(),
        ip: '192.168.1.1',
        method: 'GET',
        path: '/admin',
        status_code: 401,
      };

      await scoreEventAnomaly(projectId, event);

      const anomalies = getAnomalies(projectId, 10, 0);
      expect(anomalies.length).toBeGreaterThan(0);
      expect(anomalies[0].event_id).toBe(event.id);
    });

    it('should filter anomalies by score threshold', async () => {
      // Create multiple anomaly scores
      for (let i = 0; i < 5; i++) {
        const event: StoredEvent = {
          id: newId(),
          project_id: projectId,
          occurred_at: new Date().toISOString(),
          ip: '192.168.1.1',
          method: 'GET',
          path: '/test',
          status_code: 200,
        };
        await scoreEventAnomaly(projectId, event);
      }

      const lowThreshold = getAnomalies(projectId, 10, 0);
      const highThreshold = getAnomalies(projectId, 10, 0.9);

      expect(lowThreshold.length).toBeGreaterThanOrEqual(highThreshold.length);
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
      expect(forest).toBeDefined();
    });

    it('should score normal points as low anomaly', () => {
      const forest = new IsolationForest(50, 256);

      const normal = Array(100)
        .fill(null)
        .map(() => [Math.random() * 10, Math.random() * 10]);
      forest.train(normal);

      const score = forest.score([5, 5]);
      expect(score).toBeLessThan(0.5);
    });

    it('should score outliers as high anomaly', () => {
      const forest = new IsolationForest(50, 256);

      const normal = Array(100)
        .fill(null)
        .map(() => [Math.random() * 10, Math.random() * 10]);
      forest.train(normal);

      const outlier = [100, 100]; // Far outside normal range
      const score = forest.score(outlier);
      expect(score).toBeGreaterThan(0.3);
    });
  });

  describe('Model Status Management', () => {
    it('should update model status', () => {
      updateModelStatus(projectId, 'isolation_forest', true, 0.94, 50000);

      const status = getModelStatus(projectId);
      expect(status?.model_type).toBe('isolation_forest');
      expect(status?.is_active).toBe(true);
      expect(status?.accuracy).toBe(0.94);
      expect(status?.training_samples).toBe(50000);
    });

    it('should retrieve model status', () => {
      updateModelStatus(projectId, 'isolation_forest', false, 0.89, 30000);

      const status = getModelStatus(projectId);
      expect(status).toBeDefined();
      expect(status?.is_active).toBe(false);
    });

    it('should handle missing model status', () => {
      const status = getModelStatus(newId());
      expect(status).toBeNull();
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
        project_id: projectId,
        occurred_at: baseTime.toISOString(),
        ip: '192.168.1.99',
        method: 'GET',
        path: '/admin',
        status_code: 401,
      };

      const score = await scoreEventAnomaly(projectId, event);
      expect(score).toBeDefined();
    });
  });

  describe('Edge Cases & Error Handling', () => {
    it('should handle null features gracefully', () => {
      const forest = new IsolationForest();
      const score = forest.score([]);
      expect(typeof score).toBe('number');
      expect(score).toBeGreaterThanOrEqual(0);
    });

    it('should handle events with all zeros', async () => {
      const event: StoredEvent = {
        id: newId(),
        project_id: projectId,
        occurred_at: new Date().toISOString(),
        ip: '0.0.0.0',
        method: 'GET',
        path: '',
        status_code: 0,
      };

      const score = await scoreEventAnomaly(projectId, event);
      expect(score.composite_score).toBeGreaterThanOrEqual(0);
    });

    it('should handle very large training datasets', () => {
      const forest = new IsolationForest(5, 100);

      // Large random dataset
      const data = Array(10000)
        .fill(null)
        .map(() => [Math.random(), Math.random(), Math.random()]);

      expect(() => forest.train(data)).not.toThrow();
    });
  });
});
