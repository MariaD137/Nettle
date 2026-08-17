# Phase 13: Advanced Analytics - ML-Based Anomaly Detection

## Overview

Elevate detection beyond rule-based patterns. ML-based analytics learn normal traffic behavior and identify deviations as potential threats, catching zero-day attacks missed by signatures.

## Scope

### 1. Behavioral Baseline Learning
- **Traffic Profiling**: Learn normal patterns per project/endpoint/user
- **Statistical Models**: Mean, variance, percentile analysis
- **Time-Series Analysis**: Detect seasonality, trends, anomalies
- **Baseline Calculation**: Per-hour, per-day, per-week granularity

**Key Metrics:**
- Request rate (baseline & current)
- Error rate (4xx/5xx ratio)
- Response time distribution
- Geographic distribution of IPs
- User-Agent diversity
- HTTP method distribution

### 2. Anomaly Detection Algorithms

#### Z-Score Anomaly Detection
```
z_score = (value - mean) / std_dev
anomaly_threshold = 2.5 (2.5σ deviation)
```
**Use case:** Detect sudden spikes in traffic volume

#### Isolation Forest
- Random forest for outlier isolation
- Low computational cost
- Effective for multivariate data
- Scores: 0-1 (closer to 1 = more anomalous)

**Use case:** Detect unusual combinations (high volume + low error + single IP)

#### LSTM (Long Short-Term Memory)
- Recurrent neural network for time-series
- Learns temporal patterns
- Detects gradual deviations
- Training: 2-4 weeks of historical data

**Use case:** Detect slow credential stuffing, low-rate DDoS

#### Isolation Forest for Multivariate Analysis
```
anomaly_score = isolation_path_length / average_path_length
threshold = 0.6 (configurable)
```

### 3. Feature Engineering

**Time-Based Features:**
- Hour of day (0-23)
- Day of week (0-6)
- Is weekend? (binary)
- Is business hours? (9-17, UTC)
- Time since last request from IP

**Statistical Features:**
- Request rate (requests/min)
- Error rate (failed/total)
- Response time percentiles (p50, p95, p99)
- Unique paths per IP (entropy)
- Unique user-agents per IP

**Geographic Features:**
- IP geolocation (country, ASN)
- Distance from previous IP (km)
- VPN/Proxy detection
- Datacenter IP detection

**Content Features:**
- Request path length
- Query string length
- User-Agent entropy
- Referer presence/length
- Custom header patterns

### 4. Anomaly Types

| Type | Detection | Score Impact |
|------|-----------|--------------|
| **Traffic Spike** | Request rate > mean + 3σ | High |
| **Sudden Errors** | Error rate jump > 2σ | Medium-High |
| **Geographic Anomaly** | IP from unusual country | Medium |
| **Slow Rate Attack** | Sustained low-rate over hours | Medium |
| **Multi-Vector** | High rate + high errors + single IP | Critical |

### 5. Database Schema

```sql
CREATE TABLE ml_baselines (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  metric_name TEXT NOT NULL,
  aggregation_period TEXT,  -- 'hourly', 'daily', 'weekly'
  value REAL NOT NULL,      -- mean/median
  std_dev REAL,             -- standard deviation
  percentile_50 REAL,
  percentile_95 REAL,
  percentile_99 REAL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (project_id) REFERENCES projects(id)
);
CREATE INDEX idx_ml_baselines_project ON ml_baselines(project_id, metric_name);

CREATE TABLE anomaly_scores (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  event_id TEXT NOT NULL,
  z_score REAL,
  isolation_score REAL,
  lstm_score REAL,
  composite_score REAL,    -- weighted average 0-1
  anomaly_type TEXT,       -- 'spike', 'error_jump', 'geographic', etc
  is_anomaly BOOLEAN,      -- composite_score > threshold
  created_at TEXT NOT NULL,
  FOREIGN KEY (project_id) REFERENCES projects(id)
);
CREATE INDEX idx_anomaly_scores_project_time ON anomaly_scores(project_id, created_at);

CREATE TABLE ml_model_status (
  project_id TEXT PRIMARY KEY,
  model_type TEXT,         -- 'isolation_forest', 'lstm'
  trained_at TEXT,
  training_samples INTEGER,
  last_updated_at TEXT,
  accuracy REAL,           -- 0-1
  is_active BOOLEAN,
  FOREIGN KEY (project_id) REFERENCES projects(id)
);
```

### 6. Detection Pipeline Integration

```
Event → Built-in Signals (10) → Custom Rules (N) → ML Anomaly Score → Risk Scoring
                                                           ↓
                                                   Composite Confidence
                                                   (rules + ML weighted)
```

**Scoring Formula:**
```
final_confidence = (
  0.4 * rules_confidence +
  0.35 * ml_anomaly_score +
  0.25 * custom_rules_confidence
)
```

### 7. REST API Endpoints

#### Get Baseline Metrics
```
GET /api/analytics/:projectId/baselines?metric=request_rate&period=hourly
Response: {
  "baselines": [
    { "hour": 0, "mean": 45.2, "std_dev": 12.1, "p95": 78.3 },
    { "hour": 1, "mean": 38.9, "std_dev": 10.5, "p95": 62.1 },
    ...
  ]
}
```

#### Get Anomaly Scores
```
GET /api/analytics/:projectId/anomalies?limit=50&score_min=0.7
Response: {
  "anomalies": [
    {
      "id": "anom_123",
      "event_id": "event_456",
      "z_score": 3.2,
      "isolation_score": 0.85,
      "composite_score": 0.82,
      "anomaly_type": "traffic_spike",
      "is_anomaly": true
    }
  ]
}
```

#### Get Model Status
```
GET /api/analytics/:projectId/model-status
Response: {
  "isolation_forest": {
    "is_active": true,
    "trained_at": "2026-08-10T00:00:00Z",
    "training_samples": 250000,
    "accuracy": 0.94
  },
  "lstm": {
    "is_active": false,
    "trained_at": null,
    "reason": "Requires 2+ weeks historical data"
  }
}
```

#### Request Dashboard Data
```
GET /api/analytics/:projectId/dashboard?timeframe=24h
Response: {
  "request_rate": { "baseline": 125, "current": 450, "deviation": 3.6 },
  "error_rate": { "baseline": 0.05, "current": 0.15 },
  "top_anomalies": [...],
  "model_performance": {...}
}
```

### 8. Frontend Dashboard

**Analytics Page Components:**
- **Baseline Chart**: Historical traffic patterns with confidence bands
- **Anomaly Timeline**: Visual markers for detected anomalies
- **Metric Comparison**: Current vs baseline with deviation %
- **Model Performance**: Accuracy, precision, recall metrics
- **Alert Correlation**: Show which rules/ML triggered alert

## Implementation Strategy

### Phase 13.1: Infrastructure (3-4 hours)
- [ ] Database schema migration
- [ ] Baseline calculation service
- [ ] Statistics utility library (mean, std_dev, percentiles)
- [ ] Data collection job (hourly aggregation)

### Phase 13.2: Isolation Forest (3-4 hours)
- [ ] Implement simple isolation forest
- [ ] Feature engineering pipeline
- [ ] Training on historical data
- [ ] Scoring new events in real-time

### Phase 13.3: Z-Score Detection (1-2 hours)
- [ ] Z-score calculation service
- [ ] Threshold configuration per metric
- [ ] Integration with detection pipeline

### Phase 13.4: LSTM (4-6 hours, optional)
- [ ] LSTM model architecture
- [ ] Training pipeline
- [ ] Inference optimization
- [ ] Requires TensorFlow/PyTorch

### Phase 13.5: Frontend & Testing (3-4 hours)
- [ ] Analytics dashboard UI
- [ ] Model status visualization
- [ ] Anomaly score display in incidents
- [ ] 30+ test cases

### Phase 13.6: Documentation (2 hours)
- [ ] ML algorithms guide
- [ ] Tuning parameters reference
- [ ] API documentation
- [ ] Examples and use cases

**Total Estimated Time: 16-23 hours**

## Key Algorithms

### Isolation Forest (Simple Implementation)
```typescript
class IsolationForest {
  constructor(n_trees: number = 100, sample_size: number = 256) {
    this.n_trees = n_trees;
    this.sample_size = sample_size;
    this.trees = [];
  }

  train(X: number[][]): void {
    for (let i = 0; i < this.n_trees; i++) {
      const sample = this.randomSample(X, this.sample_size);
      const tree = this.buildTree(sample, 0);
      this.trees.push(tree);
    }
  }

  score(x: number[]): number {
    // Average isolation path length
    const pathLengths = this.trees.map(tree => this.pathLength(tree, x));
    const avgPathLength = pathLengths.reduce((a, b) => a + b) / pathLengths.length;
    
    // Anomaly score: normalized path length
    const c = this.averagePathLengthUnsuccessfulSearch(this.sample_size);
    return Math.pow(2, -avgPathLength / c);
  }

  private buildTree(X: number[][], depth: number): TreeNode {
    if (X.length <= 1 || depth >= Math.log2(this.sample_size)) {
      return { isLeaf: true, size: X.length };
    }

    const featureIndex = Math.floor(Math.random() * X[0].length);
    const splitValue = this.randomValue(X.map(x => x[featureIndex]));

    const left = X.filter(x => x[featureIndex] < splitValue);
    const right = X.filter(x => x[featureIndex] >= splitValue);

    return {
      isLeaf: false,
      featureIndex,
      splitValue,
      left: this.buildTree(left, depth + 1),
      right: this.buildTree(right, depth + 1),
    };
  }
}
```

### Z-Score Detection
```typescript
function calculateZScore(value: number, mean: number, stdDev: number): number {
  if (stdDev === 0) return value === mean ? 0 : Infinity;
  return (value - mean) / stdDev;
}

function isAnomaly(zScore: number, threshold: number = 2.5): boolean {
  return Math.abs(zScore) > threshold;
}
```

## Success Criteria

- ✓ Baselines calculated for 10+ metrics
- ✓ Isolation forest scores events in <5ms
- ✓ Detects 95%+ of traffic anomalies
- ✓ False positive rate < 5%
- ✓ Model retrains daily with latest data
- ✓ Dashboard shows baseline + current metrics
- ✓ 30+ test cases passing
- ✓ Full documentation with examples

## Performance Targets

| Metric | Target |
|--------|--------|
| Baseline calculation | < 2s per project |
| Anomaly scoring | < 5ms per event |
| Model training | < 10s per project/day |
| Memory per model | < 10MB |
| Accuracy (TP rate) | > 95% |
| False positive rate | < 5% |
| Feature engineering | < 1ms per event |

## Metrics

| Item | Count |
|------|-------|
| New database tables | 3 |
| API endpoints | 4 |
| Detection algorithms | 3 (Z-score, Isolation Forest, LSTM) |
| Features engineered | 15+ |
| Test cases | 30+ |
| Documentation pages | 1 comprehensive guide |

## Risk Mitigation

- **Cold Start**: Require 7 days baseline before ML scoring
- **Data Quality**: Validate baselines before activating
- **Performance**: Cache baseline calculations hourly
- **Overfitting**: Use cross-validation on historical data
- **Explainability**: Log which features triggered anomaly

## Optional Enhancements

- Clustering for attack pattern discovery
- Autoencoder for unsupervised learning
- Kalman filters for gradual drift
- Ensemble methods combining multiple algorithms
- Per-endpoint baselines (not just per-project)

## Dependencies

- Existing Tier 2 detection
- Custom rules engine (Phase 12)
- PostgreSQL with custom analytics schema
- Redis for baseline caching
- Optional: TensorFlow.js for LSTM

