import { db, newId } from '../db/index';
import type { StoredEvent } from './types';

export interface Baseline {
  id: string;
  metric_name: string;
  value: number;
  std_dev: number;
  percentile_50: number;
  percentile_95: number;
  percentile_99: number;
}

export interface AnomalyScore {
  id: string;
  event_id: string;
  z_score?: number;
  isolation_score?: number;
  composite_score: number;
  anomaly_type?: string;
  is_anomaly: boolean;
}

export interface ModelStatus {
  project_id: string;
  model_type: string;
  trained_at?: string;
  training_samples: number;
  accuracy?: number;
  is_active: boolean;
}

// Statistical utilities
function mean(values: number[]): number {
  if (values.length === 0) return 0;
  return values.reduce((a, b) => a + b, 0) / values.length;
}

function stdDev(values: number[]): number {
  if (values.length < 2) return 0;
  const avg = mean(values);
  const variance = values.reduce((sum, val) => sum + Math.pow(val - avg, 2), 0) / (values.length - 1);
  return Math.sqrt(variance);
}

function percentile(values: number[], p: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.max(0, index)];
}

// Calculate baselines for a project from recent events
export async function calculateBaselines(projectId: string, hoursBack: number = 24) {
  try {
    // Get recent events
    const events = db.prepare(`
      SELECT *
      FROM events
      WHERE project_id = ? AND occurred_at > datetime('now', ? || ' hours')
      ORDER BY occurred_at DESC
    `).all(projectId, -hoursBack) as StoredEvent[];

    if (events.length === 0) return { error: 'No events found' };

    // Calculate metrics by hour
    const metricsPerHour: { [hour: number]: any } = {};
    for (let h = 0; h < 24; h++) {
      metricsPerHour[h] = [];
    }

    for (const event of events) {
      const hour = new Date(event.occurredAt).getHours();
      metricsPerHour[hour].push(event);
    }

    // Generate baselines
    const baselines = [];
    const now = new Date().toISOString();

    for (let hour = 0; hour < 24; hour++) {
      const hourEvents = metricsPerHour[hour];
      if (hourEvents.length === 0) continue;

      // Request rate (events per minute)
      const requestRate = (hourEvents.length / hoursBack) * 60;
      const baseline = {
        id: newId(),
        project_id: projectId,
        metric_name: 'request_rate',
        aggregation_period: 'hourly',
        hour_of_day: hour,
        day_of_week: null,
        value: requestRate,
        std_dev: 0,
        percentile_50: 0,
        percentile_95: 0,
        percentile_99: 0,
        updated_at: now,
      };

      db.prepare(`
        INSERT OR REPLACE INTO ml_baselines
        (id, project_id, metric_name, aggregation_period, hour_of_day, value, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        baseline.id,
        projectId,
        baseline.metric_name,
        baseline.aggregation_period,
        hour,
        requestRate,
        now
      );

      baselines.push(baseline);

      // Error rate
      const errors = hourEvents.filter((e: any) => e.status_code >= 400).length;
      const errorRate = errors / hourEvents.length;

      db.prepare(`
        INSERT OR REPLACE INTO ml_baselines
        (id, project_id, metric_name, aggregation_period, hour_of_day, value, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(
        newId(),
        projectId,
        'error_rate',
        'hourly',
        hour,
        errorRate,
        now
      );
    }

    return { baselines_calculated: baselines.length };
  } catch (error) {
    return { error: 'Failed to calculate baselines' };
  }
}

// Get baseline for a metric
export function getBaseline(projectId: string, metricName: string, hour?: number): Baseline | null {
  let query = 'SELECT * FROM ml_baselines WHERE project_id = ? AND metric_name = ?';
  const params: any[] = [projectId, metricName];

  if (hour !== undefined) {
    query += ' AND hour_of_day = ?';
    params.push(hour);
  }

  query += ' ORDER BY updated_at DESC LIMIT 1';
  const row = db.prepare(query).get(...params) as any;

  return row
    ? {
        id: row.id,
        metric_name: row.metric_name,
        value: row.value,
        std_dev: row.std_dev || 0,
        percentile_50: row.percentile_50 || 0,
        percentile_95: row.percentile_95 || 0,
        percentile_99: row.percentile_99 || 0,
      }
    : null;
}

// Calculate Z-score anomaly
function calculateZScore(value: number, mean: number, stdDev: number): number {
  if (stdDev === 0) return value === mean ? 0 : 3;
  return Math.abs((value - mean) / stdDev);
}

function isZScoreAnomaly(zScore: number, threshold: number = 2.5): boolean {
  return zScore > threshold;
}

// Simple Isolation Forest implementation
export class IsolationForest {
  private trees: any[] = [];
  private nTrees: number;
  private sampleSize: number;

  constructor(nTrees: number = 50, sampleSize: number = 256) {
    this.nTrees = nTrees;
    this.sampleSize = sampleSize;
  }

  train(features: number[][]): void {
    for (let i = 0; i < this.nTrees; i++) {
      const sample = this.randomSample(features, this.sampleSize);
      const tree = this.buildTree(sample, 0);
      this.trees.push(tree);
    }
  }

  score(feature: number[]): number {
    if (this.trees.length === 0) return 0;

    const pathLengths = this.trees.map(tree => this.pathLength(tree, feature, 0));
    const avgPathLength = pathLengths.reduce((a, b) => a + b) / pathLengths.length;

    // Normalize anomaly score to 0-1
    const c = this.averagePathLengthOfUnsuccessfulSearch(this.sampleSize);
    const anomalyScore = Math.pow(2, -avgPathLength / c);

    return Math.min(1, Math.max(0, anomalyScore));
  }

  private randomSample(data: any[], size: number): any[] {
    const sample = [];
    const indices = new Set<number>();
    while (indices.size < Math.min(size, data.length)) {
      indices.add(Math.floor(Math.random() * data.length));
    }
    return Array.from(indices).map(i => data[i]);
  }

  private buildTree(data: any[], depth: number): any {
    if (data.length <= 1 || depth >= Math.log2(this.sampleSize)) {
      return { isLeaf: true, size: data.length };
    }

    const featureIndex = Math.floor(Math.random() * (data[0]?.length || 1));
    const values = data.map(d => d[featureIndex]).sort((a, b) => a - b);
    const splitValue = values[Math.floor(values.length / 2)];

    const left = data.filter(d => d[featureIndex] < splitValue);
    const right = data.filter(d => d[featureIndex] >= splitValue);

    return {
      isLeaf: false,
      featureIndex,
      splitValue,
      left: this.buildTree(left, depth + 1),
      right: this.buildTree(right, depth + 1),
    };
  }

  private pathLength(tree: any, feature: number[], depth: number): number {
    if (tree.isLeaf) {
      return depth + this.logarithm(tree.size - 1);
    }

    const featureValue = feature[tree.featureIndex];
    if (featureValue < tree.splitValue) {
      return this.pathLength(tree.left, feature, depth + 1);
    } else {
      return this.pathLength(tree.right, feature, depth + 1);
    }
  }

  private logarithm(n: number): number {
    return Math.log2(Math.max(1, n));
  }

  private averagePathLengthOfUnsuccessfulSearch(n: number): number {
    if (n <= 1) return 0;
    return 2 * (Math.log2(n - 1) + 0.5772156649) - (2 * (n - 1)) / n;
  }
}

// Extract features from event
export function extractFeatures(event: StoredEvent, baseline?: any): number[] {
  const hour = new Date(event.occurredAt).getHours();

  // Normalize features to 0-1 scale
  const features = [
    (event.statusCode || 200) / 599, // HTTP status code (0-1)
    event.path?.length ? Math.min(event.path.length, 2000) / 2000 : 0, // Path length
    event.userAgent?.length ? Math.min(event.userAgent.length, 500) / 500 : 0, // User-Agent length
    hour / 23, // Hour of day (0-1)
    event.method === 'POST' ? 1 : 0, // Is POST method
    event.method === 'GET' ? 1 : 0, // Is GET method
    event.statusCode && event.statusCode >= 400 ? 1 : 0, // Is error
  ];

  return features;
}

// Calculate composite anomaly score
export async function scoreEventAnomaly(
  projectId: string,
  event: StoredEvent,
  baseline?: Baseline
): Promise<AnomalyScore> {
  const id = newId();
  const hour = new Date(event.occurredAt).getHours();

  let zScore = 0;
  let isolationScore = 0;
  let isAnomaly = false;
  let anomalyType = '';

  // Z-score detection on request rate
  const rateBaseline = getBaseline(projectId, 'request_rate', hour);
  if (rateBaseline && rateBaseline.std_dev > 0) {
    zScore = calculateZScore(1, rateBaseline.value, rateBaseline.std_dev); // 1 event = rate increase
    if (isZScoreAnomaly(zScore)) {
      isAnomaly = true;
      anomalyType = 'traffic_spike';
    }
  }

  // Isolation Forest on features
  const features = extractFeatures(event);
  const model = getModelStatus(projectId);
  if (model?.is_active) {
    // In production, would load serialized model from cache
    // For now, use simple scoring
    isolationScore = Math.random(); // Placeholder
  }

  // Composite score (weighted average)
  const compositeScore = zScore > 0 ? Math.min(1, zScore / 3) : isolationScore;

  if (compositeScore > 0.7) {
    isAnomaly = true;
    if (!anomalyType) anomalyType = 'behavioral_anomaly';
  }

  // Store score
  db.prepare(`
    INSERT INTO anomaly_scores
    (id, project_id, event_id, z_score, isolation_score, composite_score, anomaly_type, is_anomaly, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    projectId,
    event.id || '',
    zScore || null,
    isolationScore || null,
    compositeScore,
    anomalyType || null,
    isAnomaly ? 1 : 0,
    new Date().toISOString()
  );

  return {
    id,
    event_id: event.id || '',
    z_score: zScore,
    isolation_score: isolationScore,
    composite_score: compositeScore,
    anomaly_type: anomalyType,
    is_anomaly: isAnomaly,
  };
}

// Get model status
export function getModelStatus(projectId: string): ModelStatus | null {
  const row = db.prepare(
    'SELECT * FROM ml_model_status WHERE project_id = ?'
  ).get(projectId) as any;

  return row
    ? {
        project_id: row.project_id,
        model_type: row.model_type,
        trained_at: row.trained_at,
        training_samples: row.training_samples || 0,
        accuracy: row.accuracy,
        is_active: row.is_active === 1,
      }
    : null;
}

// Update model status
export function updateModelStatus(
  projectId: string,
  modelType: string,
  isActive: boolean,
  accuracy?: number,
  trainingSamples?: number
): void {
  db.prepare(`
    INSERT OR REPLACE INTO ml_model_status
    (project_id, model_type, is_active, accuracy, training_samples, trained_at, last_update_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    projectId,
    modelType,
    isActive ? 1 : 0,
    accuracy || null,
    trainingSamples || 0,
    new Date().toISOString(),
    new Date().toISOString()
  );
}

// Get anomalies
export function getAnomalies(projectId: string, limit: number = 50, scoreMin: number = 0.7): AnomalyScore[] {
  const rows = db.prepare(`
    SELECT * FROM anomaly_scores
    WHERE project_id = ? AND composite_score >= ?
    ORDER BY created_at DESC
    LIMIT ?
  `).all(projectId, scoreMin, limit) as any[];

  return rows.map(row => ({
    id: row.id,
    event_id: row.event_id,
    z_score: row.z_score,
    isolation_score: row.isolation_score,
    composite_score: row.composite_score,
    anomaly_type: row.anomaly_type,
    is_anomaly: row.is_anomaly === 1,
  }));
}
