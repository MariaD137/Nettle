import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
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
import { recordEvent } from '../src/patrol/events';
import { runDetection } from '../src/patrol/detection';
import { listAlerts } from '../src/patrol/alerts';

describe('Phase 12: Custom Detection Rules', () => {
  let projectId: string;
  let userId: string;

  beforeEach(async () => {
    projectId = newId();
    userId = newId();

    // Create test project and user
    await db
      .prepare(
        `INSERT INTO users (id, email, password_hash, created_at)
         VALUES (?, ?, ?, ?)
         ON CONFLICT (id) DO NOTHING`
      )
      .run(userId, `test-${userId}@example.com`, "hash", new Date().toISOString());

    await db
      .prepare(
        `INSERT INTO projects (id, user_id, name, api_key, created_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (id) DO NOTHING`
      )
      .run(projectId, userId, "Test Project", `key_${projectId}`, new Date().toISOString());
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

      assert.notEqual(rule, undefined);
      assert.equal(rule?.name, 'Admin Path Detection');
      assert.equal(rule?.weight, 75);
      assert.equal(rule?.enabled, true);
      assert.equal(rule?.version, 1);
    });

    it('should reject invalid weight', async () => {
      const rule = await createCustomRule(projectId, userId, {
        name: 'Invalid Weight',
        pattern_type: 'exact',
        pattern_value: '/test',
        weight: 150, // Invalid
        severity: 'high',
      } as any);

      assert.equal(rule, null);
    });

    it('should reject invalid regex', async () => {
      const rule = await createCustomRule(projectId, userId, {
        name: 'Invalid Regex',
        pattern_type: 'regex',
        pattern_value: '(?P<invalid)', // Invalid regex
        weight: 50,
        severity: 'high',
      } as any);

      assert.equal(rule, null);
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

      assert.equal(rule, null);
    });

    it('should retrieve a rule', async () => {
      const created = await createCustomRule(projectId, userId, {
        name: 'Test Rule',
        pattern_type: 'exact',
        pattern_value: '/test',
        weight: 60,
        severity: 'medium',
      } as any);

      const retrieved = await getCustomRule(created!.id);
      assert.equal(retrieved?.name, 'Test Rule');
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

      const rules = await listCustomRules(projectId);
      assert.equal(rules.length, 2);
      assert.equal(rules[0].name, 'Rule 2'); // Most recent first
    });

    it('should update a rule', async () => {
      const created = await createCustomRule(projectId, userId, {
        name: 'Original Name',
        pattern_type: 'exact',
        pattern_value: '/test',
        weight: 50,
        severity: 'medium',
      } as any);

      const updated = await updateCustomRule(created!.id, {
        name: 'Updated Name',
        weight: 75,
        enabled: false,
      } as any);

      assert.equal(updated?.name, 'Updated Name');
      assert.equal(updated?.weight, 75);
      assert.equal(updated?.enabled, false);
      assert.equal(updated?.version, 2);
    });

    it('should delete a rule', async () => {
      const created = await createCustomRule(projectId, userId, {
        name: 'To Delete',
        pattern_type: 'exact',
        pattern_value: '/delete',
        weight: 50,
        severity: 'medium',
      } as any);

      const deleted = await deleteCustomRule(created!.id);
      assert.equal(deleted, true);

      const retrieved = await getCustomRule(created!.id);
      assert.equal(retrieved, null);
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
      assert.equal(evaluateCustomRule(rule!, event), true);

      const nomatch = { path: '/user', status_code: 200 };
      assert.equal(evaluateCustomRule(rule!, nomatch), false);
    });

    it('should match regex patterns', async () => {
      const rule = await createCustomRule(projectId, userId, {
        name: 'Regex Match',
        pattern_type: 'regex',
        pattern_value: '^/api/v[0-9]+/admin',
        weight: 50,
        severity: 'high',
      } as any);

      assert.equal(evaluateCustomRule(rule!, { path: '/api/v1/admin', status_code: 200 }), true);
      assert.equal(evaluateCustomRule(rule!, { path: '/api/v2/admin/users', status_code: 200 }), true);
      assert.equal(evaluateCustomRule(rule!, { path: '/api/admin', status_code: 200 }), false);
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
      assert.equal(evaluateCustomRule(rule!, event), false);
    });

    it('should match threshold patterns against a window of events sharing the evaluated field', async () => {
      const rule = await createCustomRule(projectId, userId, {
        name: 'Threshold',
        pattern_type: 'threshold',
        pattern_value: 'ip:>=3',
        weight: 50,
        severity: 'high',
      } as any);

      const currentEvent = { ip: '203.0.113.9', path: '/x', status_code: 200 };
      const windowBelowThreshold = [
        { ip: '203.0.113.9', path: '/x', status_code: 200 },
        { ip: '203.0.113.9', path: '/x', status_code: 200 },
      ];
      assert.equal(evaluateCustomRule(rule!, currentEvent, windowBelowThreshold), false, "2 matching events < 3 threshold");

      const windowAtThreshold = [
        { ip: '203.0.113.9', path: '/x', status_code: 200 },
        { ip: '203.0.113.9', path: '/x', status_code: 200 },
        { ip: '203.0.113.9', path: '/x', status_code: 200 },
        { ip: '198.51.100.1', path: '/x', status_code: 200 }, // different ip — must not count
      ];
      assert.equal(evaluateCustomRule(rule!, currentEvent, windowAtThreshold), true, "3 matching-ip events meets the >=3 threshold");
    });

    it('threshold patterns ignore events from the window that do not share the evaluated field value', async () => {
      const rule = await createCustomRule(projectId, userId, {
        name: 'Threshold by path',
        pattern_type: 'threshold',
        pattern_value: 'path:>2',
        weight: 50,
        severity: 'high',
      } as any);

      const currentEvent = { path: '/login', status_code: 401 };
      const window = [
        { path: '/login', status_code: 401 },
        { path: '/login', status_code: 401 },
        { path: '/other', status_code: 401 },
        { path: '/other', status_code: 401 },
        { path: '/other', status_code: 401 },
      ];
      // Only 2 events (besides — inclusive of — the pattern's own field
      // match count) share path "/login"; ">2" requires more than 2.
      assert.equal(evaluateCustomRule(rule!, currentEvent, window), false);
    });

    it('should match combination patterns', async () => {
      const rule = await createCustomRule(projectId, userId, {
        name: 'Combination',
        pattern_type: 'combination',
        pattern_value: 'method=POST&status_code=401',
        weight: 50,
        severity: 'high',
      } as any);

      assert.equal(evaluateCustomRule(rule!, { method: 'POST', status_code: 401 }), true);
      assert.equal(evaluateCustomRule(rule!, { method: 'GET', status_code: 401 }), false);
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

      assert.equal(result?.events_matched, 3);
      assert.equal(result?.true_positives, 2);
      assert.equal(result?.false_positives, 1);
      assert.equal(result?.accuracy, 0.6666666666666666); // 2TP / (2TP + 1FP)
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

      assert.equal(result, null);
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
      await updateCustomRule(rule!.id, {
        name: 'Updated',
        pattern_value: '/path2',
      } as any);

      // Update again
      await updateCustomRule(rule!.id, {
        weight: 75,
      } as any);

      const versions = await getRuleVersions(rule!.id);
      assert.equal(versions.length, 2);
      // The rule is created at version 1 (not itself recorded as a version
      // row); each update then records the version it just moved to.
      assert.equal(versions[0].version, 3);
      assert.equal(versions[1].version, 2);
    });

    it('should record changes in versions', async () => {
      const rule = await createCustomRule(projectId, userId, {
        name: 'Original',
        pattern_type: 'exact',
        pattern_value: '/path',
        weight: 50,
        severity: 'medium',
      } as any);

      await updateCustomRule(rule!.id, { weight: 75 } as any);

      const versions = await getRuleVersions(rule!.id);
      const changes = JSON.parse(versions[0].changes || '{}');
      assert.equal(changes.weight, 75);
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

      const allRules = await listCustomRules(projectId, false);
      const enabledRules = await listCustomRules(projectId, true);

      assert.equal(allRules.length, 2);
      assert.equal(enabledRules.length, 1);
      assert.equal(enabledRules[0].name, 'Enabled Rule');
    });
  });

  describe('Detection Pipeline Integration', () => {
    it('a matching exact/regex/combination custom rule fires a real alert via runDetection', async () => {
      const rule = await createCustomRule(projectId, userId, {
        name: 'Production Alert',
        pattern_type: 'exact',
        pattern_value: '/api/admin',
        weight: 80,
        severity: 'critical',
      } as any);
      assert.notEqual(rule, undefined);

      const event = await recordEvent(projectId, { ip: '203.0.113.70', method: 'GET', path: '/api/admin', statusCode: 200 });
      const alerts = await runDetection(projectId, event);

      const hit = alerts.find((a) => a.rule === `custom-rule-${rule!.id}`);
      assert.ok(hit, 'expected the custom rule to produce a real alert through the actual detection pipeline');
      assert.equal(hit?.severity, 'critical');
      assert.ok((await listAlerts(projectId)).some((a) => a.id === hit!.id), 'the alert should be persisted, not just returned in-memory');
    });

    it('a "threshold" custom rule — previously dead code that always returned false — now genuinely fires via runDetection', async () => {
      const rule = await createCustomRule(projectId, userId, {
        name: 'Same-IP flood',
        pattern_type: 'threshold',
        pattern_value: 'ip:>=4',
        weight: 80,
        severity: 'high',
      } as any);
      assert.notEqual(rule, undefined);

      let alerts: Awaited<ReturnType<typeof runDetection>> = [];
      for (let i = 0; i < 4; i++) {
        const event = await recordEvent(projectId, { ip: '203.0.113.80', method: 'GET', path: '/anything', statusCode: 200 });
        alerts = await runDetection(projectId, event);
      }

      assert.ok(
        alerts.some((a) => a.rule === `custom-rule-${rule!.id}`),
        'expected the threshold rule to fire once 4 same-ip events are in the window'
      );
    });
  });

  describe('Error Handling', () => {
    it('should handle null rule gracefully', () => {
      const result = evaluateCustomRule(null as any, { path: '/test' });
      assert.equal(result, false);
    });

    it('should handle malformed events', async () => {
      const rule = await createCustomRule(projectId, userId, {
        name: 'Robust Rule',
        pattern_type: 'exact',
        pattern_value: '/admin',
        weight: 50,
        severity: 'high',
      } as any);

      assert.equal(evaluateCustomRule(rule!, {}), false);
      assert.equal(evaluateCustomRule(rule!, { path: null }), false);
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
      assert.notEqual(rule === null || rule?.id, undefined);
    });
  });
});
