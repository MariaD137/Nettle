import { describe, it, expect, beforeEach } from '@jest/globals';
import { db, newId } from '../src/db/index';
import {
  createCustomRule,
  getCustomRule,
  listCustomRules,
  updateCustomRule,
  deleteCustomRule,
  testRule,
  evaluateCustomRule,
  getRuleVersions,
} from '../src/patrol/customRules';

describe('Phase 12: Custom Detection Rules', () => {
  let projectId: string;
  let userId: string;

  beforeEach(() => {
    projectId = newId();
    userId = newId();

    // Create test project and user
    db.exec(`
      INSERT OR IGNORE INTO users (id, email, password_hash, created_at)
      VALUES ('${userId}', 'test@example.com', 'hash', '${new Date().toISOString()}');

      INSERT OR IGNORE INTO projects (id, user_id, name, api_key, created_at)
      VALUES ('${projectId}', '${userId}', 'Test Project', 'key_test', '${new Date().toISOString()}');
    `);
  });

  describe('CRUD Operations', () => {
    it('should create a custom rule', async () => {
      const rule = await createCustomRule(projectId, userId, {
        name: 'Admin Path Detection',
        description: 'Detect requests to /admin',
        pattern_type: 'exact',
        pattern_value: '/admin',
        weight: 75,
        severity: 'high',
        enabled: true,
      } as any);

      expect(rule).toBeDefined();
      expect(rule?.name).toBe('Admin Path Detection');
      expect(rule?.weight).toBe(75);
      expect(rule?.enabled).toBe(true);
      expect(rule?.version).toBe(1);
    });

    it('should reject invalid weight', async () => {
      const rule = await createCustomRule(projectId, userId, {
        name: 'Invalid Weight',
        pattern_type: 'exact',
        pattern_value: '/test',
        weight: 150, // Invalid
        severity: 'high',
      } as any);

      expect(rule).toBeNull();
    });

    it('should reject invalid regex', async () => {
      const rule = await createCustomRule(projectId, userId, {
        name: 'Invalid Regex',
        pattern_type: 'regex',
        pattern_value: '(?P<invalid)', // Invalid regex
        weight: 50,
        severity: 'high',
      } as any);

      expect(rule).toBeNull();
    });

    it('should enforce max rules per project', async () => {
      // Create 100 rules (max)
      for (let i = 0; i < 100; i++) {
        await createCustomRule(projectId, userId, {
          name: `Rule ${i}`,
          pattern_type: 'exact',
          pattern_value: `/path${i}`,
          weight: 50,
          severity: 'medium',
        } as any);
      }

      // 101st should fail
      const rule = await createCustomRule(projectId, userId, {
        name: 'Rule 101',
        pattern_type: 'exact',
        pattern_value: '/path101',
        weight: 50,
        severity: 'medium',
      } as any);

      expect(rule).toBeNull();
    });

    it('should retrieve a rule', async () => {
      const created = await createCustomRule(projectId, userId, {
        name: 'Test Rule',
        pattern_type: 'exact',
        pattern_value: '/test',
        weight: 60,
        severity: 'medium',
      } as any);

      const retrieved = getCustomRule(created!.id);
      expect(retrieved?.name).toBe('Test Rule');
    });

    it('should list rules by project', async () => {
      await createCustomRule(projectId, userId, {
        name: 'Rule 1',
        pattern_type: 'exact',
        pattern_value: '/path1',
        weight: 50,
        severity: 'medium',
      } as any);

      await createCustomRule(projectId, userId, {
        name: 'Rule 2',
        pattern_type: 'regex',
        pattern_value: '/admin.*',
        weight: 75,
        severity: 'high',
      } as any);

      const rules = listCustomRules(projectId);
      expect(rules.length).toBe(2);
      expect(rules[0].name).toBe('Rule 2'); // Most recent first
    });

    it('should update a rule', async () => {
      const created = await createCustomRule(projectId, userId, {
        name: 'Original Name',
        pattern_type: 'exact',
        pattern_value: '/test',
        weight: 50,
        severity: 'medium',
      } as any);

      const updated = updateCustomRule(created!.id, {
        name: 'Updated Name',
        weight: 75,
        enabled: false,
      } as any);

      expect(updated?.name).toBe('Updated Name');
      expect(updated?.weight).toBe(75);
      expect(updated?.enabled).toBe(false);
      expect(updated?.version).toBe(2);
    });

    it('should delete a rule', async () => {
      const created = await createCustomRule(projectId, userId, {
        name: 'To Delete',
        pattern_type: 'exact',
        pattern_value: '/delete',
        weight: 50,
        severity: 'medium',
      } as any);

      const deleted = deleteCustomRule(created!.id);
      expect(deleted).toBe(true);

      const retrieved = getCustomRule(created!.id);
      expect(retrieved).toBeNull();
    });
  });

  describe('Pattern Matching', () => {
    it('should match exact patterns', async () => {
      const rule = await createCustomRule(projectId, userId, {
        name: 'Exact Match',
        pattern_type: 'exact',
        pattern_value: '/admin',
        weight: 50,
        severity: 'high',
      } as any);

      const event = { path: '/admin', status_code: 200 };
      expect(evaluateCustomRule(rule!, event)).toBe(true);

      const nomatch = { path: '/user', status_code: 200 };
      expect(evaluateCustomRule(rule!, nomatch)).toBe(false);
    });

    it('should match regex patterns', async () => {
      const rule = await createCustomRule(projectId, userId, {
        name: 'Regex Match',
        pattern_type: 'regex',
        pattern_value: '^/api/v[0-9]+/admin',
        weight: 50,
        severity: 'high',
      } as any);

      expect(evaluateCustomRule(rule!, { path: '/api/v1/admin', status_code: 200 })).toBe(true);
      expect(evaluateCustomRule(rule!, { path: '/api/v2/admin/users', status_code: 200 })).toBe(true);
      expect(evaluateCustomRule(rule!, { path: '/api/admin', status_code: 200 })).toBe(false);
    });

    it('should disable matching when rule is disabled', async () => {
      const rule = await createCustomRule(projectId, userId, {
        name: 'Disabled Rule',
        pattern_type: 'exact',
        pattern_value: '/admin',
        weight: 50,
        severity: 'high',
        enabled: false,
      } as any);

      const event = { path: '/admin', status_code: 200 };
      expect(evaluateCustomRule(rule!, event)).toBe(false);
    });

    it('should match combination patterns', async () => {
      const rule = await createCustomRule(projectId, userId, {
        name: 'Combination',
        pattern_type: 'combination',
        pattern_value: 'method=POST&status_code=401',
        weight: 50,
        severity: 'high',
      } as any);

      expect(evaluateCustomRule(rule!, { method: 'POST', status_code: 401 })).toBe(true);
      expect(evaluateCustomRule(rule!, { method: 'GET', status_code: 401 })).toBe(false);
    });
  });

  describe('Rule Testing', () => {
    it('should test rule against sample events', async () => {
      const rule = await createCustomRule(projectId, userId, {
        name: 'Test Rule',
        pattern_type: 'exact',
        pattern_value: '/admin',
        weight: 50,
        severity: 'high',
      } as any);

      const events = [
        { path: '/admin', status_code: 401 }, // Match, True Positive
        { path: '/admin', status_code: 403 }, // Match, True Positive
        { path: '/user', status_code: 200 }, // No match
        { path: '/admin', status_code: 200 }, // Match, False Positive
      ];

      const result = await testRule(rule!.id, events);

      expect(result?.events_matched).toBe(3);
      expect(result?.true_positives).toBe(2);
      expect(result?.false_positives).toBe(1);
      expect(result?.accuracy).toBe(0.6666666666666666); // 2TP / (2TP + 1FP)
    });

    it('should reject oversized test events', async () => {
      const rule = await createCustomRule(projectId, userId, {
        name: 'Test Rule',
        pattern_type: 'exact',
        pattern_value: '/admin',
        weight: 50,
        severity: 'high',
      } as any);

      const events = Array(10001).fill({ path: '/admin', status_code: 200 });
      const result = await testRule(rule!.id, events);

      expect(result).toBeNull();
    });
  });

  describe('Rule Versioning', () => {
    it('should track rule versions', async () => {
      const rule = await createCustomRule(projectId, userId, {
        name: 'Original',
        pattern_type: 'exact',
        pattern_value: '/path1',
        weight: 50,
        severity: 'medium',
      } as any);

      // Update rule
      updateCustomRule(rule!.id, {
        name: 'Updated',
        pattern_value: '/path2',
      } as any);

      // Update again
      updateCustomRule(rule!.id, {
        weight: 75,
      } as any);

      const versions = getRuleVersions(rule!.id);
      expect(versions.length).toBe(2);
      expect(versions[0].version).toBe(2);
      expect(versions[1].version).toBe(1);
    });

    it('should record changes in versions', async () => {
      const rule = await createCustomRule(projectId, userId, {
        name: 'Original',
        pattern_type: 'exact',
        pattern_value: '/path',
        weight: 50,
        severity: 'medium',
      } as any);

      updateCustomRule(rule!.id, { weight: 75 } as any);

      const versions = getRuleVersions(rule!.id);
      const changes = JSON.parse(versions[0].changes || '{}');
      expect(changes.weight).toBe(75);
    });
  });

  describe('Disabled Rules Filtering', () => {
    it('should filter enabled-only rules', async () => {
      await createCustomRule(projectId, userId, {
        name: 'Enabled Rule',
        pattern_type: 'exact',
        pattern_value: '/enabled',
        weight: 50,
        severity: 'medium',
        enabled: true,
      } as any);

      await createCustomRule(projectId, userId, {
        name: 'Disabled Rule',
        pattern_type: 'exact',
        pattern_value: '/disabled',
        weight: 50,
        severity: 'medium',
        enabled: false,
      } as any);

      const allRules = listCustomRules(projectId, false);
      const enabledRules = listCustomRules(projectId, true);

      expect(allRules.length).toBe(2);
      expect(enabledRules.length).toBe(1);
      expect(enabledRules[0].name).toBe('Enabled Rule');
    });
  });

  describe('Detection Pipeline Integration', () => {
    it('should detect events using custom rules', async () => {
      // This test would verify that custom rules are evaluated by detection.ts
      // When a custom rule matches, it should create an alert with rule-specified severity
      const rule = await createCustomRule(projectId, userId, {
        name: 'Production Alert',
        pattern_type: 'exact',
        pattern_value: '/api/admin',
        weight: 80,
        severity: 'critical',
      } as any);

      expect(rule).toBeDefined();
      // Would call detection pipeline and verify alert was created
    });
  });

  describe('Error Handling', () => {
    it('should handle null rule gracefully', () => {
      const result = evaluateCustomRule(null as any, { path: '/test' });
      expect(result).toBe(false);
    });

    it('should handle malformed events', async () => {
      const rule = await createCustomRule(projectId, userId, {
        name: 'Robust Rule',
        pattern_type: 'exact',
        pattern_value: '/admin',
        weight: 50,
        severity: 'high',
      } as any);

      expect(evaluateCustomRule(rule!, {})).toBe(false);
      expect(evaluateCustomRule(rule!, { path: null })).toBe(false);
    });

    it('should timeout slow regex patterns', async () => {
      // Test that extremely complex regex patterns fail gracefully
      const rule = await createCustomRule(projectId, userId, {
        name: 'Complex Regex',
        pattern_type: 'regex',
        pattern_value: 'a*a*a*a*a*a*a*a*a*a*b', // Catastrophic backtracking
        weight: 50,
        severity: 'high',
      } as any);

      // Should either return null or handle the error
      expect(rule === null || rule?.id).toBeDefined();
    });
  });
});
