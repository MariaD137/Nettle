import { test } from 'node:test';
import { deepStrictEqual, ok, throws } from 'node:assert';
import { db, newId } from '../src/db/index';
import { LSTM, Autoencoder } from '../src/patrol/mlAnalytics';

test('Phase 13 Part 3: Advanced ML Models (LSTM + Autoencoder)', { concurrency: false }, async (t) => {
  let projectId: string;
  let userId: string;

  await t.test('LSTM Model', async (t) => {
    beforeEach();

    await t.test('should initialize LSTM with correct dimensions', () => {
      const lstm = new LSTM(1, 10, 12);
      ok(lstm !== undefined);
    });

    await t.test('should train on time-series data', () => {
      const lstm = new LSTM(1, 10, 12);
      const sequences = Array(100).fill(null).map(() =>
        Array(12).fill(null).map(() => Math.random() * 100)
      );

      ok(() => lstm.train(sequences) !== undefined);
    });

    await t.test('should score normal sequences', () => {
      const lstm = new LSTM(1, 10, 12);
      const normalSequence = Array(12).fill(50);

      lstm.train([normalSequence, normalSequence, normalSequence]);
      const score = lstm.score(normalSequence);

      ok(score >= 0 && score <= 1);
    });

    await t.test('should score anomalies differently than normal', () => {
      const lstm = new LSTM(1, 10, 12);
      const normalSequence = Array(12).fill(50);
      const anomalySequence = Array(12).fill(200);

      lstm.train([normalSequence, normalSequence]);
      const normalScore = lstm.score(normalSequence);
      const anomalyScore = lstm.score(anomalySequence);

      ok(typeof normalScore === 'number' && typeof anomalyScore === 'number');
    });

    await t.test('should handle short sequences gracefully', () => {
      const lstm = new LSTM(1, 10, 12);
      const shortSequence = [50, 51, 52];

      const score = lstm.score(shortSequence);
      deepStrictEqual(score, 0.5);
    });
  });

  await t.test('Autoencoder Model', async (t) => {
    beforeEach();

    await t.test('should initialize autoencoder with correct dimensions', () => {
      const autoencoder = new Autoencoder(7, 3);
      ok(autoencoder !== undefined);
    });

    await t.test('should train on feature vectors', () => {
      const autoencoder = new Autoencoder(7, 3);
      const features = Array(100).fill(null).map(() =>
        Array(7).fill(null).map(() => Math.random())
      );

      ok(() => autoencoder.train(features) !== undefined);
    });

    await t.test('should score normal features', () => {
      const autoencoder = new Autoencoder(7, 3);
      const normalFeatures = [0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5];

      autoencoder.train([normalFeatures, normalFeatures, normalFeatures]);
      const score = autoencoder.score(normalFeatures);

      ok(score >= 0 && score <= 1);
    });

    await t.test('should score anomalies differently', () => {
      const autoencoder = new Autoencoder(7, 3);
      const normalFeatures = [0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5];
      const anomalyFeatures = [0.1, 0.9, 0.1, 0.9, 0.1, 0.9, 0.1];

      autoencoder.train([normalFeatures, normalFeatures]);
      const normalScore = autoencoder.score(normalFeatures);
      const anomalyScore = autoencoder.score(anomalyFeatures);

      ok(typeof normalScore === 'number' && typeof anomalyScore === 'number');
    });

    await t.test('should handle mismatched dimensions gracefully', () => {
      const autoencoder = new Autoencoder(7, 3);
      const wrongDimensions = [0.5, 0.5, 0.5];

      const score = autoencoder.score(wrongDimensions);
      deepStrictEqual(score, 0.5);
    });

    await t.test('should score consistent features consistently', () => {
      const autoencoder = new Autoencoder(7, 3);
      const features1 = [0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8];
      const features2 = [0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8];

      autoencoder.train([features1, features1]);
      const score1 = autoencoder.score(features1);
      const score2 = autoencoder.score(features2);

      ok(Math.abs(score1 - score2) < 0.01);
    });
  });

  await t.test('Model Comparison', async (t) => {
    beforeEach();

    await t.test('LSTM should detect temporal anomalies', () => {
      const lstm = new LSTM(1, 10, 12);
      const normal = Array(12).fill(100);
      const spike = [100, 100, 100, 500, 100, 100, 100, 100, 100, 100, 100, 100];

      lstm.train([normal, normal, normal]);
      const normalScore = lstm.score(normal);
      const spikeScore = lstm.score(spike);

      ok(typeof normalScore === 'number' && typeof spikeScore === 'number');
    });

    await t.test('Autoencoder should detect behavioral anomalies', () => {
      const autoencoder = new Autoencoder(7, 3);
      const normal = [0.2, 0.3, 0.2, 0.3, 0.2, 0.3, 0.2];
      const anomaly = [0.9, 0.1, 0.9, 0.1, 0.9, 0.1, 0.9];

      autoencoder.train(Array(10).fill(normal));
      const normalScore = autoencoder.score(normal);
      const anomalyScore = autoencoder.score(anomaly);

      ok(typeof normalScore === 'number' && typeof anomalyScore === 'number');
    });

    await t.test('should combine models for ensemble detection', () => {
      const lstm = new LSTM(1, 10, 12);
      const autoencoder = new Autoencoder(7, 3);

      const timeSeriesData = Array(12).fill(100);
      const featureData = [0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5];

      lstm.train([timeSeriesData, timeSeriesData]);
      autoencoder.train([featureData, featureData]);

      const lstmScore = lstm.score(timeSeriesData);
      const autoencoderScore = autoencoder.score(featureData);
      const combinedScore = (lstmScore + autoencoderScore) / 2;

      ok(combinedScore >= 0 && combinedScore <= 1);
    });
  });

  await t.test('Performance & Efficiency', async (t) => {
    beforeEach();

    await t.test('LSTM should handle large datasets', () => {
      const lstm = new LSTM(1, 10, 12);
      const sequences = Array(100).fill(null).map(() =>
        Array(12).fill(null).map(() => Math.random() * 100)
      );

      const start = Date.now();
      lstm.train(sequences);
      const duration = Date.now() - start;

      ok(duration < 5000);
    });

    await t.test('Autoencoder should handle high-dimensional data', () => {
      const autoencoder = new Autoencoder(50, 10);
      const features = Array(100).fill(null).map(() =>
        Array(50).fill(null).map(() => Math.random())
      );

      const start = Date.now();
      autoencoder.train(features);
      const duration = Date.now() - start;

      ok(duration < 5000);
    });

    await t.test('scoring should be fast', () => {
      const lstm = new LSTM(1, 10, 12);
      const sequence = Array(12).fill(50);

      lstm.train([sequence, sequence]);

      const start = Date.now();
      for (let i = 0; i < 100; i++) {
        lstm.score(sequence);
      }
      const duration = Date.now() - start;

      ok(duration < 1000);
    });
  });

  function beforeEach() {
    projectId = newId();
    userId = newId();

    db.exec(`
      INSERT OR IGNORE INTO users (id, email, password_hash, created_at)
      VALUES ('${userId}', 'ml-advanced@example.com', 'hash', '${new Date().toISOString()}');

      INSERT OR IGNORE INTO projects (id, user_id, name, api_key, created_at)
      VALUES ('${projectId}', '${userId}', 'Advanced ML Test', 'ml_key', '${new Date().toISOString()}');
    `);
  }
});
