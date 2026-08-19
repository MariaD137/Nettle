import { Router, Request, Response } from 'express';
import { db } from '../db/index';
import {
  calculateBaselines,
  getBaseline,
  scoreEventAnomaly,
  getModelStatus,
  getAnomalies,
} from '../patrol/mlAnalytics';
import { requireAuth } from '../auth/middleware';
import { getOwnedProject } from '../patrol/projectAccess';

const router = Router();

// Verify project ownership
function verifyProjectAccess(req: Request, res: Response, next: Function) {
  const { projectId } = req.params;
  const userId = req.userId;

  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const project = getOwnedProject(projectId, userId);
  if (!project) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  next();
}

// POST /api/analytics/:projectId/calculate-baselines
router.post(
  '/:projectId/calculate-baselines',
  requireAuth,
  verifyProjectAccess,
  async (req: Request, res: Response) => {
    const { projectId } = req.params;
    const { hoursBack } = req.body;

    const result = await calculateBaselines(projectId, hoursBack || 24);

    if ('error' in result) {
      return res.status(400).json(result);
    }

    res.json(result);
  }
);

// GET /api/analytics/:projectId/baselines
router.get(
  '/:projectId/baselines',
  requireAuth,
  verifyProjectAccess,
  (req: Request, res: Response) => {
    const { projectId } = req.params;
    const { metric, period, hour } = req.query;

    let query = 'SELECT * FROM ml_baselines WHERE project_id = ?';
    const params: any[] = [projectId];

    if (metric) {
      query += ' AND metric_name = ?';
      params.push(metric);
    }

    if (period) {
      query += ' AND aggregation_period = ?';
      params.push(period);
    }

    if (hour !== undefined) {
      query += ' AND hour_of_day = ?';
      params.push(parseInt(hour as string));
    }

    query += ' ORDER BY hour_of_day ASC';

    const rows = db.prepare(query).all(...params) as any[];
    const baselines = rows.map(row => ({
      id: row.id,
      metric_name: row.metric_name,
      hour_of_day: row.hour_of_day,
      value: row.value,
      std_dev: row.std_dev,
      percentile_50: row.percentile_50,
      percentile_95: row.percentile_95,
      percentile_99: row.percentile_99,
      updated_at: row.updated_at,
    }));

    res.json({ baselines });
  }
);

// GET /api/analytics/:projectId/anomalies
router.get(
  '/:projectId/anomalies',
  requireAuth,
  verifyProjectAccess,
  (req: Request, res: Response) => {
    const { projectId } = req.params;
    const { limit = '50', score_min = '0.7' } = req.query;

    const anomalies = getAnomalies(projectId, parseInt(limit as string), parseFloat(score_min as string));

    res.json({ anomalies });
  }
);

// GET /api/analytics/:projectId/model-status
router.get(
  '/:projectId/model-status',
  requireAuth,
  verifyProjectAccess,
  (req: Request, res: Response) => {
    const { projectId } = req.params;

    const status = getModelStatus(projectId);

    if (!status) {
      return res.json({
        isolation_forest: { is_active: false, reason: 'Not trained' },
        lstm: { is_active: false, reason: 'Requires 2+ weeks data' },
      });
    }

    res.json({
      model_type: status.model_type,
      is_active: status.is_active,
      trained_at: status.trained_at,
      training_samples: status.training_samples,
      accuracy: status.accuracy,
    });
  }
);

// GET /api/analytics/:projectId/dashboard
router.get(
  '/:projectId/dashboard',
  requireAuth,
  verifyProjectAccess,
  async (req: Request, res: Response) => {
    const { projectId } = req.params;
    const { timeframe = '24h' } = req.query;

    // Get recent events
    const events = db.prepare(`
      SELECT COUNT(*) as count,
             SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as errors
      FROM events
      WHERE project_id = ? AND occurred_at > datetime('now', '-24 hours')
    `).get(projectId) as any;

    const requestCount = events?.count || 0;
    const errorCount = events?.errors || 0;
    const errorRate = requestCount > 0 ? (errorCount / requestCount) * 100 : 0;

    // Get current baseline
    const hour = new Date().getHours();
    const rateBaseline = getBaseline(projectId, 'request_rate', hour);
    const errorBaseline = getBaseline(projectId, 'error_rate', hour);

    // Get recent anomalies
    const anomalies = getAnomalies(projectId, 5, 0.7);

    // Get model status. getModelStatus() returns null until a model has
    // actually been trained for this project — true for every project by
    // default, since nothing trains one automatically — so this needs the
    // same "not trained yet" fallback the dedicated /model-status endpoint
    // above already has, just in the flat shape this response (and the
    // frontend's ModelStatus component) actually uses.
    const modelStatus = getModelStatus(projectId) ?? {
      model_type: null,
      is_active: false,
      trained_at: null,
      training_samples: 0,
      accuracy: null,
    };

    res.json({
      metrics: {
        request_count: requestCount,
        error_rate: errorRate,
        request_baseline: rateBaseline?.value || 0,
        error_baseline: errorBaseline?.value || 0,
      },
      anomalies,
      model_status: modelStatus,
    });
  }
);

export default router;
