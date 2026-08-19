import { Router, Request, Response, NextFunction } from 'express';
import { getOwnedProject } from '../patrol/projectAccess';
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
  CustomRuleInput,
} from '../patrol/customRules';
import { requireAuth } from '../auth/middleware';
import { asyncHandler } from '../middleware/asyncHandler';

const router = Router();

// Middleware to verify project ownership
const verifyProjectAccess = asyncHandler(async (req: Request, res: Response, next: NextFunction) => {
  const { projectId } = req.params;
  const userId = req.userId;

  if (!userId) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const project = await getOwnedProject(projectId, userId);
  if (!project) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  (req as any).project = project;
  next();
});

// Fetches a rule and verifies it actually belongs to the project in the URL
// (not just that the caller owns *some* project) — ruleId alone is not
// sufficient to authorize access to a rule.
async function getOwnedRule(ruleId: string, projectId: string): Promise<CustomRule | null> {
  const rule = await getCustomRule(ruleId);
  if (!rule || rule.project_id !== projectId) return null;
  return rule;
}

// POST /api/custom-rules/:projectId
router.post(
  '/:projectId',
  requireAuth,
  verifyProjectAccess,
  asyncHandler(async (req: Request, res: Response) => {
    const { projectId } = req.params;
    const userId = req.userId!;
    const { name, description, pattern_type, pattern_value, weight, severity, enabled } = req.body;

    if (!name || !pattern_type || !pattern_value) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    if (!['exact', 'regex', 'threshold', 'combination'].includes(pattern_type)) {
      return res.status(400).json({ error: 'Invalid pattern_type' });
    }

    const ruleInput: CustomRuleInput = {
      name,
      description,
      pattern_type: pattern_type as CustomRule['pattern_type'],
      pattern_value,
      weight: weight || 50,
      severity: severity || 'medium',
      enabled: enabled !== false,
    };
    const rule = await createCustomRule(projectId, userId, ruleInput);

    if (!rule) {
      return res.status(400).json({ error: 'Failed to create rule' });
    }

    res.status(201).json(rule);
  })
);

// GET /api/custom-rules/:projectId
router.get(
  '/:projectId',
  requireAuth,
  verifyProjectAccess,
  asyncHandler(async (req: Request, res: Response) => {
    const { projectId } = req.params;
    const { enabledOnly } = req.query;

    const rules = await listCustomRules(projectId, enabledOnly === 'true');
    res.json({ rules });
  })
);

// GET /api/custom-rules/:projectId/:ruleId
router.get(
  '/:projectId/:ruleId',
  requireAuth,
  verifyProjectAccess,
  asyncHandler(async (req: Request, res: Response) => {
    const { projectId, ruleId } = req.params;

    const rule = await getOwnedRule(ruleId, projectId);
    if (!rule) {
      return res.status(404).json({ error: 'Rule not found' });
    }

    res.json(rule);
  })
);

// PATCH /api/custom-rules/:projectId/:ruleId
router.patch(
  '/:projectId/:ruleId',
  requireAuth,
  verifyProjectAccess,
  asyncHandler(async (req: Request, res: Response) => {
    const { projectId, ruleId } = req.params;
    const existing = await getOwnedRule(ruleId, projectId);

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

    const updated = await updateCustomRule(ruleId, updates as any);
    if (!updated) {
      return res.status(400).json({ error: 'Failed to update rule' });
    }

    res.json(updated);
  })
);

// DELETE /api/custom-rules/:projectId/:ruleId
router.delete(
  '/:projectId/:ruleId',
  requireAuth,
  verifyProjectAccess,
  asyncHandler(async (req: Request, res: Response) => {
    const { projectId, ruleId } = req.params;

    if (!(await getOwnedRule(ruleId, projectId)) || !(await deleteCustomRule(ruleId))) {
      return res.status(404).json({ error: 'Rule not found' });
    }

    res.json({ deleted: true });
  })
);

// POST /api/custom-rules/:projectId/:ruleId/test
router.post(
  '/:projectId/:ruleId/test',
  requireAuth,
  verifyProjectAccess,
  asyncHandler(async (req: Request, res: Response) => {
    const { projectId, ruleId } = req.params;
    const { events } = req.body;

    if (!(await getOwnedRule(ruleId, projectId))) {
      return res.status(404).json({ error: 'Rule not found' });
    }

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
  })
);

// GET /api/custom-rules/:projectId/:ruleId/versions
router.get(
  '/:projectId/:ruleId/versions',
  requireAuth,
  verifyProjectAccess,
  asyncHandler(async (req: Request, res: Response) => {
    const { projectId, ruleId } = req.params;

    if (!(await getOwnedRule(ruleId, projectId))) {
      return res.status(404).json({ error: 'Rule not found' });
    }

    const versions = await getRuleVersions(ruleId);
    res.json({ versions });
  })
);

// GET /api/custom-rules/:projectId/:ruleId/test-results
router.get(
  '/:projectId/:ruleId/test-results',
  requireAuth,
  verifyProjectAccess,
  asyncHandler(async (req: Request, res: Response) => {
    const { projectId, ruleId } = req.params;
    const { limit } = req.query;

    if (!(await getOwnedRule(ruleId, projectId))) {
      return res.status(404).json({ error: 'Rule not found' });
    }

    const results = await getTestResults(ruleId, parseInt(limit as string) || 10);
    res.json({ results });
  })
);

export default router;
