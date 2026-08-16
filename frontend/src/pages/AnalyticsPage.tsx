import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import './AnalyticsPage.css';

interface Baseline {
  metric_name: string;
  hour_of_day: number;
  value: number;
  std_dev: number;
  percentile_95: number;
  updated_at: string;
}

interface Anomaly {
  id: string;
  event_id: string;
  z_score?: number;
  isolation_score?: number;
  composite_score: number;
  anomaly_type?: string;
  is_anomaly: boolean;
}

interface ModelStatus {
  model_type: string;
  is_active: boolean;
  trained_at?: string;
  training_samples: number;
  accuracy?: number;
}

interface DashboardData {
  metrics: {
    request_count: number;
    error_rate: number;
    request_baseline: number;
    error_baseline: number;
  };
  anomalies: Anomaly[];
  model_status: ModelStatus;
}

export function AnalyticsPage() {
  const { projectId } = useParams<{ projectId: string }>();
  const [data, setData] = useState<DashboardData | null>(null);
  const [baselines, setBaselines] = useState<Baseline[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [recalculating, setRecalculating] = useState(false);

  useEffect(() => {
    if (projectId) loadDashboard();
  }, [projectId]);

  async function loadDashboard() {
    try {
      setLoading(true);
      const [dashResponse, baselinesResponse] = await Promise.all([
        fetch(`http://localhost:3000/api/analytics/${projectId}/dashboard?timeframe=24h`, {
          headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` },
        }),
        fetch(`http://localhost:3000/api/analytics/${projectId}/baselines?metric=request_rate&period=hourly`, {
          headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` },
        }),
      ]);

      if (dashResponse.ok && baselinesResponse.ok) {
        const dashData = await dashResponse.json();
        const baselineData = await baselinesResponse.json();
        setData(dashData);
        setBaselines(baselineData.baselines || []);
      } else {
        setError('Failed to load analytics data');
      }
    } catch (err) {
      setError('Error loading analytics');
    } finally {
      setLoading(false);
    }
  }

  async function recalculateBaselines() {
    try {
      setRecalculating(true);
      const response = await fetch(
        `http://localhost:3000/api/analytics/${projectId}/calculate-baselines`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ hoursBack: 24 }),
        }
      );

      if (response.ok) {
        loadDashboard();
      }
    } catch (err) {
      setError('Failed to recalculate baselines');
    } finally {
      setRecalculating(false);
    }
  }

  if (loading) return <div className="loading">Loading analytics...</div>;

  return (
    <div className="analytics-page">
      <div className="page-header">
        <h1>ML Analytics & Anomaly Detection</h1>
        <button
          className="btn-primary"
          onClick={recalculateBaselines}
          disabled={recalculating}
        >
          {recalculating ? 'Recalculating...' : 'Recalculate Baselines'}
        </button>
      </div>

      {error && <div className="error-message">{error}</div>}

      {data && (
        <>
          <MetricsGrid metrics={data.metrics} />
          <AnomalyTimeline anomalies={data.anomalies} />
          <BaselineChart baselines={baselines} />
          <ModelStatus status={data.model_status} />
        </>
      )}
    </div>
  );
}

interface MetricsGridProps {
  metrics: DashboardData['metrics'];
}

function MetricsGrid({ metrics }: MetricsGridProps) {
  const requestDeviation = metrics.request_baseline > 0
    ? (((metrics.request_count - metrics.request_baseline) / metrics.request_baseline) * 100).toFixed(1)
    : '0';

  const errorDeviation = (metrics.error_rate * 100).toFixed(2);
  const errorBaselinePercent = (metrics.error_baseline * 100).toFixed(2);

  return (
    <div className="metrics-grid">
      <MetricCard
        title="Request Rate"
        value={metrics.request_count}
        unit="requests/24h"
        baseline={metrics.request_baseline}
        deviation={parseFloat(requestDeviation)}
        trend={parseFloat(requestDeviation) > 20 ? 'up' : 'stable'}
      />
      <MetricCard
        title="Error Rate"
        value={parseFloat(errorDeviation)}
        unit="%"
        baseline={parseFloat(errorBaselinePercent)}
        deviation={parseFloat(errorDeviation) - parseFloat(errorBaselinePercent)}
        trend={parseFloat(errorDeviation) > parseFloat(errorBaselinePercent) ? 'up' : 'down'}
      />
      <MetricCard
        title="Request Baseline"
        value={metrics.request_baseline}
        unit="requests/24h"
        trend="neutral"
      />
      <MetricCard
        title="Error Baseline"
        value={parseFloat(errorBaselinePercent)}
        unit="%"
        trend="neutral"
      />
    </div>
  );
}

interface MetricCardProps {
  title: string;
  value: number;
  unit: string;
  baseline?: number;
  deviation?: number;
  trend: 'up' | 'down' | 'stable' | 'neutral';
}

function MetricCard({ title, value, unit, baseline, deviation, trend }: MetricCardProps) {
  const trendIcon = {
    up: '↑',
    down: '↓',
    stable: '→',
    neutral: '−',
  }[trend];

  const trendColor = {
    up: '#ff6600',
    down: '#0066cc',
    stable: '#999',
    neutral: '#999',
  }[trend];

  return (
    <div className="metric-card">
      <h3>{title}</h3>
      <div className="metric-value">
        {value.toFixed(2)} <span className="unit">{unit}</span>
      </div>
      {baseline !== undefined && (
        <div className="metric-baseline">
          Baseline: {baseline.toFixed(2)} {unit}
        </div>
      )}
      {deviation !== undefined && (
        <div className="metric-deviation" style={{ color: trendColor }}>
          {trendIcon} {deviation > 0 ? '+' : ''}{deviation.toFixed(1)}%
        </div>
      )}
    </div>
  );
}

interface AnomalyTimelineProps {
  anomalies: Anomaly[];
}

function AnomalyTimeline({ anomalies }: AnomalyTimelineProps) {
  if (anomalies.length === 0) {
    return (
      <div className="anomaly-timeline">
        <h2>Recent Anomalies</h2>
        <div className="empty-state">No anomalies detected in the last 24 hours</div>
      </div>
    );
  }

  return (
    <div className="anomaly-timeline">
      <h2>Recent Anomalies ({anomalies.length})</h2>
      <div className="timeline-items">
        {anomalies.slice(0, 10).map((anomaly) => (
          <AnomalyItem key={anomaly.id} anomaly={anomaly} />
        ))}
      </div>
    </div>
  );
}

function AnomalyItem({ anomaly }: { anomaly: Anomaly }) {
  const scorePercent = Math.round(anomaly.composite_score * 100);
  const severity = getSeverity(anomaly.composite_score);

  return (
    <div className={`anomaly-item severity-${severity}`}>
      <div className="anomaly-header">
        <span className="anomaly-type">{anomaly.anomaly_type || 'behavioral'}</span>
        <span className={`anomaly-score score-${severity}`}>
          {scorePercent}% confidence
        </span>
      </div>
      <div className="anomaly-details">
        {anomaly.z_score && (
          <span className="detail">Z-Score: {anomaly.z_score.toFixed(2)}</span>
        )}
        {anomaly.isolation_score && (
          <span className="detail">
            Isolation: {(anomaly.isolation_score * 100).toFixed(0)}%
          </span>
        )}
      </div>
      <div className="progress-bar">
        <div
          className={`progress-fill ${severity}`}
          style={{ width: `${scorePercent}%` }}
        />
      </div>
    </div>
  );
}

interface BaselineChartProps {
  baselines: Baseline[];
}

function BaselineChart({ baselines }: BaselineChartProps) {
  if (baselines.length === 0) {
    return (
      <div className="baseline-chart">
        <h2>Request Rate Baseline (24h Pattern)</h2>
        <div className="empty-state">No baseline data available. Recalculate to generate baselines.</div>
      </div>
    );
  }

  const maxValue = Math.max(...baselines.map(b => b.value + (b.std_dev || 0)));
  const chartHeight = 200;
  const barWidth = 100 / baselines.length;

  return (
    <div className="baseline-chart">
      <h2>Request Rate Baseline (24h Pattern)</h2>
      <div className="chart-container">
        <div className="chart-bars">
          {baselines.map((baseline, idx) => (
            <div
              key={idx}
              className="bar-group"
              style={{ width: `${barWidth}%` }}
              title={`Hour ${baseline.hour_of_day}: ${baseline.value.toFixed(1)} ± ${(baseline.std_dev || 0).toFixed(1)}`}
            >
              <div className="confidence-band" style={{
                height: `${((baseline.value + (baseline.std_dev || 0)) / maxValue) * chartHeight}px`,
                opacity: 0.2,
              }} />
              <div className="baseline-bar" style={{
                height: `${(baseline.value / maxValue) * chartHeight}px`,
              }} />
              <span className="hour-label">{baseline.hour_of_day}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="chart-legend">
        <span className="legend-item">
          <span className="legend-color" style={{ backgroundColor: '#0066cc' }} />
          Baseline (mean)
        </span>
        <span className="legend-item">
          <span className="legend-color" style={{ backgroundColor: 'rgba(0, 102, 204, 0.2)' }} />
          Confidence band (±1σ)
        </span>
      </div>
    </div>
  );
}

interface ModelStatusProps {
  status: ModelStatus;
}

function ModelStatus({ status }: ModelStatusProps) {
  const statusText = status.is_active ? 'Active' : 'Inactive';
  const statusColor = status.is_active ? '#00aa00' : '#999';

  return (
    <div className="model-status">
      <h2>ML Model Status</h2>
      <div className="status-grid">
        <div className="status-item">
          <label>Model Type</label>
          <div className="status-value">{status.model_type || 'isolation_forest'}</div>
        </div>
        <div className="status-item">
          <label>Status</label>
          <div className="status-value" style={{ color: statusColor }}>
            {statusText}
          </div>
        </div>
        {status.trained_at && (
          <div className="status-item">
            <label>Trained At</label>
            <div className="status-value">
              {new Date(status.trained_at).toLocaleDateString()}
            </div>
          </div>
        )}
        <div className="status-item">
          <label>Training Samples</label>
          <div className="status-value">{status.training_samples.toLocaleString()}</div>
        </div>
        {status.accuracy && (
          <div className="status-item">
            <label>Accuracy</label>
            <div className="status-value">{(status.accuracy * 100).toFixed(1)}%</div>
          </div>
        )}
      </div>
    </div>
  );
}

function getSeverity(score: number): 'critical' | 'high' | 'medium' | 'low' {
  if (score >= 0.9) return 'critical';
  if (score >= 0.7) return 'high';
  if (score >= 0.5) return 'medium';
  return 'low';
}
