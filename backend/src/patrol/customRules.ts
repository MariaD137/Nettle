import { db, newId } from '../db/index';
import crypto from 'crypto';

export interface CustomRule {
  id: string;
  project_id: string;
  name: string;
  description?: string;
  pattern_type: 'exact' | 'regex' | 'threshold' | 'combination';
  pattern_value: string;
  weight: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  enabled: boolean;
  version: number;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface RuleVersion {
  id: string;
  rule_id: string;
  version: number;
  pattern_value: string;
  weight: number;
  severity: string;
  changes?: string;
  created_by: string;
  created_at: string;
}

export interface TestResult {
  id: string;
  rule_id: string;
  test_run_id: string;
  events_matched: number;
  true_positives: number;
  false_positives: number;
  accuracy?: number;
  execution_time_ms?: number;
  created_at: string;
}

// Pattern matching cache
const regexCache = new Map<string, RegExp>();
const MAX_RULES_PER_PROJECT = 100;

function getOrCompileRegex(pattern: string): RegExp | null {
  try {
    if (regexCache.has(pattern)) {
      return regexCache.get(pattern)!;
    }
    const regex = new RegExp(pattern);
    regexCache.set(pattern, regex);
    return regex;
  } catch {
    return null;
  }
}

function matchExact(event: any, pattern: string, field: string): boolean {
  return event[field] === pattern;
}

function matchRegex(event: any, pattern: string, field: string): boolean {
  const regex = getOrCompileRegex(pattern);
  if (!regex) return false;
  const value = event[field];
  return value && regex.test(String(value));
}

function matchThreshold(events: any[], pattern: string): boolean {
  try {
    const [fieldName, operator, threshold] = pattern.split(':');
    if (!fieldName || !operator || !threshold) return false;

    const count = events.length;
    const thresholdNum = parseInt(threshold, 10);

    switch (operator) {
      case '>':
        return count > thresholdNum;
      case '>=':
        return count >= thresholdNum;
      case '<':
        return count < thresholdNum;
      case '<=':
        return count <= thresholdNum;
      case '=':
        return count === thresholdNum;
      default:
        return false;
    }
  } catch {
    return false;
  }
}

function matchCombination(event: any, pattern: string): boolean {
  try {
    // Simple AND/OR logic: "field1=value1&field2=value2" (AND) or "field1=value1|field2=value2" (OR)
    const hasOR = pattern.includes('|');
    const conditions = pattern.split(hasOR ? '|' : '&');

    const results = conditions.map(cond => {
      const [field, value] = cond.trim().split('=');
      // event field values aren't always strings (e.g. status_code is a
      // number) while the pattern's value always is, since it comes from
      // splitting the rule text — compare as strings on both sides.
      return String(event[field]) === value;
    });

    return hasOR ? results.some(r => r) : results.every(r => r);
  } catch {
    return false;
  }
}

export type CustomRuleInput = Pick<CustomRule, 'name' | 'pattern_type' | 'pattern_value'> &
  Partial<Omit<CustomRule, 'name' | 'pattern_type' | 'pattern_value'>>;

export async function createCustomRule(
  projectId: string,
  userId: string,
  data: CustomRuleInput
): Promise<CustomRule | null> {
  try {
    // Validate rule count
    const existing = db.prepare(
      'SELECT COUNT(*) as count FROM custom_rules WHERE project_id = ?'
    ).get(projectId) as { count: number };

    if (existing.count >= MAX_RULES_PER_PROJECT) {
      return null;
    }

    // Validate pattern
    if (data.pattern_type === 'regex') {
      const regex = getOrCompileRegex(data.pattern_value!);
      if (!regex) return null;
    }

    // Validate weight
    if ((data.weight ?? 0) < 0 || (data.weight ?? 100) > 100) {
      return null;
    }

    const id = newId();
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO custom_rules
      (id, project_id, name, description, pattern_type, pattern_value, weight, severity, enabled, version, created_by, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
    `).run(
      id,
      projectId,
      data.name,
      data.description || null,
      data.pattern_type,
      data.pattern_value,
      data.weight || 50,
      data.severity || 'medium',
      data.enabled !== false ? 1 : 0,
      userId,
      now,
      now
    );

    return getCustomRule(id);
  } catch {
    return null;
  }
}

export function getCustomRule(ruleId: string): CustomRule | null {
  const row = db.prepare('SELECT * FROM custom_rules WHERE id = ?').get(ruleId) as any;
  if (!row) return null;
  return {
    ...row,
    enabled: row.enabled === 1,
  };
}

export function listCustomRules(projectId: string, enabledOnly = false): CustomRule[] {
  // created_at has only millisecond resolution, so rules created in quick
  // succession can tie — rowid DESC breaks the tie in insertion order.
  const query = enabledOnly
    ? 'SELECT * FROM custom_rules WHERE project_id = ? AND enabled = 1 ORDER BY created_at DESC, rowid DESC'
    : 'SELECT * FROM custom_rules WHERE project_id = ? ORDER BY created_at DESC, rowid DESC';

  const rows = db.prepare(query).all(projectId) as any[];
  return rows.map(row => ({
    ...row,
    enabled: row.enabled === 1,
  }));
}

export function updateCustomRule(
  ruleId: string,
  updates: Partial<CustomRule>
): CustomRule | null {
  const existing = getCustomRule(ruleId);
  if (!existing) return null;

  // If pattern changed, validate it
  if (updates.pattern_value && updates.pattern_type === 'regex') {
    const regex = getOrCompileRegex(updates.pattern_value);
    if (!regex) return null;
  }

  // Validate weight if changed
  if (updates.weight !== undefined && (updates.weight < 0 || updates.weight > 100)) {
    return null;
  }

  const now = new Date().toISOString();
  const newVersion = (existing.version || 0) + 1;

  // Record version
  db.prepare(`
    INSERT INTO rule_versions
    (id, rule_id, version, pattern_value, weight, severity, changes, created_by, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    newId(),
    ruleId,
    newVersion,
    updates.pattern_value || existing.pattern_value,
    updates.weight !== undefined ? updates.weight : existing.weight,
    updates.severity || existing.severity,
    JSON.stringify(updates),
    existing.created_by,
    now
  );

  // Update rule. Fixed column list — never built from the keys of the
  // caller-supplied `updates` object, so there's no way to inject an
  // arbitrary column name here.
  db.prepare(`
    UPDATE custom_rules
    SET name = ?, description = ?, pattern_type = ?, pattern_value = ?,
        weight = ?, severity = ?, enabled = ?, version = ?, updated_at = ?
    WHERE id = ?
  `).run(
    updates.name ?? existing.name,
    updates.description ?? existing.description ?? null,
    updates.pattern_type ?? existing.pattern_type,
    updates.pattern_value ?? existing.pattern_value,
    updates.weight !== undefined ? updates.weight : existing.weight,
    updates.severity ?? existing.severity,
    updates.enabled !== undefined ? (updates.enabled ? 1 : 0) : (existing.enabled ? 1 : 0),
    newVersion,
    now,
    ruleId
  );

  return getCustomRule(ruleId);
}

export function deleteCustomRule(ruleId: string): boolean {
  const existing = getCustomRule(ruleId);
  if (!existing) return false;

  db.prepare('DELETE FROM rule_versions WHERE rule_id = ?').run(ruleId);
  db.prepare('DELETE FROM rule_test_results WHERE rule_id = ?').run(ruleId);
  db.prepare('DELETE FROM custom_rules WHERE id = ?').run(ruleId);

  return true;
}

export function getRuleVersions(ruleId: string): RuleVersion[] {
  const rows = db.prepare(
    'SELECT * FROM rule_versions WHERE rule_id = ? ORDER BY version DESC'
  ).all(ruleId) as unknown as RuleVersion[];
  return rows;
}

export async function testRule(ruleId: string, events: any[]): Promise<TestResult | null> {
  const rule = getCustomRule(ruleId);
  if (!rule) return null;
  if (events.length > 10000) return null;

  const startTime = Date.now();
  let matched = 0;
  let truePositives = 0;
  let falsePositives = 0;

  try {
    for (const event of events) {
      let isMatch = false;

      switch (rule.pattern_type) {
        case 'exact':
          isMatch = matchExact(event, rule.pattern_value, 'path');
          break;
        case 'regex':
          isMatch = matchRegex(event, rule.pattern_value, 'path');
          break;
        case 'threshold':
          isMatch = matchThreshold(events, rule.pattern_value);
          break;
        case 'combination':
          isMatch = matchCombination(event, rule.pattern_value);
          break;
      }

      if (isMatch) {
        matched++;
        // Mark as TP if status_code >= 400, FP if < 400
        if (event.status_code >= 400) {
          truePositives++;
        } else {
          falsePositives++;
        }
      }
    }

    const executionTime = Date.now() - startTime;
    const accuracy = events.length > 0
      ? (truePositives / (truePositives + falsePositives || 1))
      : 0;

    const testRunId = newId();
    const resultId = newId();

    db.prepare(`
      INSERT INTO rule_test_results
      (id, rule_id, test_run_id, events_matched, true_positives, false_positives, accuracy, execution_time_ms, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      resultId,
      ruleId,
      testRunId,
      matched,
      truePositives,
      falsePositives,
      accuracy,
      executionTime,
      new Date().toISOString()
    );

    return {
      id: resultId,
      rule_id: ruleId,
      test_run_id: testRunId,
      events_matched: matched,
      true_positives: truePositives,
      false_positives: falsePositives,
      accuracy,
      execution_time_ms: executionTime,
      created_at: new Date().toISOString(),
    };
  } catch (error) {
    return null;
  }
}

export function evaluateCustomRule(rule: CustomRule | null, event: any): boolean {
  if (!rule || !rule.enabled) return false;

  try {
    switch (rule.pattern_type) {
      case 'exact':
        return matchExact(event, rule.pattern_value, 'path');
      case 'regex':
        return matchRegex(event, rule.pattern_value, 'path');
      case 'threshold':
        // Threshold needs event collection, return false in single-event context
        return false;
      case 'combination':
        return matchCombination(event, rule.pattern_value);
      default:
        return false;
    }
  } catch {
    return false;
  }
}

export function getTestResults(ruleId: string, limit = 10): TestResult[] {
  const rows = db.prepare(
    'SELECT * FROM rule_test_results WHERE rule_id = ? ORDER BY created_at DESC LIMIT ?'
  ).all(ruleId, limit) as unknown as TestResult[];
  return rows;
}
