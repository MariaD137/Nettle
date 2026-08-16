import { Router, Request, Response } from 'express';
import { db } from '../db/index';
import {
  createCustomRule,
  getCustomRule,
  listCustomRules,
  updateCustomRule,
  deleteCustomRule,
  testRule,
  getRuleVersions,
  getTestResults,
  CustomRule,
} from '../patrol/customRules';
import { requireAuth } from '../auth/middleware';

const router = Router();

// Middleware to verify project ownership
function verifyProjectAccess(req: Request, res: Response, next: Function) {
  const { projectId } = req.params;
  const userId = req.userId;

  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const project = db.prepare(
    'SELECT * FROM projects WHERE id = ? AND user_id = ?'
  ).get(projectId);

  if (!project) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  (req as any).project = project;
  next();
}

// POST /api/custom-rules/:projectId
router.post(
  '/:projectId',
  requireAuth,
  verifyProjectAccess,
  async (req: Request, res: Response) => {
    const { projectId } = req.params;
    const userId = req.userId!;
    const { name, description, pattern_type, pattern_value, weight, severity, enabled } = req.body;

    if (!name || !pattern_type || !pattern_value) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    if (!['exact', 'regex', 'threshold', 'combination'].includes(pattern_type)) {
      return res.status(400).json({ error: 'Invalid pattern_type' });
    }

    const rule = await createCustomRule(projectId, userId, {
      name,
      description,
      pattern_type: pattern_type as any,
      pattern_value,
      weight: weight || 50,
      severity: severity || 'medium',
      enabled: enabled !== false,
    } as any);

    if (!rule) {
      return res.status(400).json({ error: 'Failed to create rule' });
    }

    res.status(201).json(rule);
  }
);

// GET /api/custom-rules/:projectId
router.get(
  '/:projectId',
  requireAuth,
  verifyProjectAccess,
  (req: Request, res: Response) => {
    const { projectId } = req.params;
    const { enabledOnly } = req.query;

    const rules = listCustomRules(projectId, enabledOnly === 'true');
    res.json({ rules });
  }
);

// GET /api/custom-rules/:projectId/:ruleId
router.get(
  '/:projectId/:ruleId',
  requireAuth,
  verifyProjectAccess,
  (req: Request, res: Response) => {
    const { ruleId } = req.params;

    const rule = getCustomRule(ruleId);
    if (!rule) {
      return res.status(404).json({ error: 'Rule not found' });
    }

    res.json(rule);
  }
);

// PATCH /api/custom-rules/:projectId/:ruleId
router.patch(
  '/:projectId/:ruleId',
  requireAuth,
  verifyProjectAccess,
  async (req: Request, res: Response) => {
    const { ruleId } = req.params;
    const existing = getCustomRule(ruleId);

    if (!existing) {
      return res.status(404).json({ error: 'Rule not found' });
    }

    const updates = {
      name: req.body.name || existing.name,
      description: req.body.description,
      pattern_type: req.body.pattern_type || existing.pattern_type,
      pattern_value: req.body.pattern_value || existing.pattern_value,
      weight: req.body.weight !== undefined ? req.body.weight : existing.weight,
      severity: req.body.severity || existing.severity,
      enabled: req.body.enabled !== undefined ? req.body.enabled : existing.enabled,
    };

    const updated = updateCustomRule(ruleId, updates as any);
    if (!updated) {
      return res.status(400).json({ error: 'Failed to update rule' });
    }

    res.json(updated);
  }
);

// DELETE /api/custom-rules/:projectId/:ruleId
router.delete(
  '/:projectId/:ruleId',
  requireAuth,
  verifyProjectAccess,
  (req: Request, res: Response) => {
    const { ruleId } = req.params;

    if (!deleteCustomRule(ruleId)) {
      return res.status(404).json({ error: 'Rule not found' });
    }

    res.json({ deleted: true });
  }
);

// POST /api/custom-rules/:projectId/:ruleId/test
router.post(
  '/:projectId/:ruleId/test',
  requireAuth,
  verifyProjectAccess,
  async (req: Request, res: Response) => {
    const { ruleId } = req.params;
    const { events } = req.body;

    if (!Array.isArray(events) || events.length === 0) {
      return res.status(400).json({ error: 'events must be a non-empty array' });
    }

    if (events.length > 10000) {
      return res.status(400).json({ error: 'Maximum 10000 events per test' });
    }

    const result = await testRule(ruleId, events);
    if (!result) {
      return res.status(400).json({ error: 'Failed to test rule' });
    }

    res.json(result);
  }
);

// GET /api/custom-rules/:projectId/:ruleId/versions
router.get(
  '/:projectId/:ruleId/versions',
  requireAuth,
  verifyProjectAccess,
  (req: Request, res: Response) => {
    const { ruleId } = req.params;

    const versions = getRuleVersions(ruleId);
    res.json({ versions });
  }
);

// GET /api/custom-rules/:projectId/:ruleId/test-results
router.get(
  '/:projectId/:ruleId/test-results',
  requireAuth,
  verifyProjectAccess,
  (req: Request, res: Response) => {
    const { ruleId } = req.params;
    const { limit } = req.query;

    const results = getTestResults(ruleId, parseInt(limit as string) || 10);
    res.json({ results });
  }
);

export default router;
