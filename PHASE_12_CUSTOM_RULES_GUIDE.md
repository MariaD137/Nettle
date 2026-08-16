# Phase 12: Custom Detection Rules - User Guide & API Reference

## Overview

Custom Detection Rules enable you to create project-specific patterns without code changes. Build on the core detection system with patterns for your unique attack types, business logic, or compliance requirements.

## Quick Start

### 1. Create a Rule

**Via Dashboard:**
1. Navigate to your project
2. Click "Custom Rules" in the menu
3. Click "+ Create Rule"
4. Fill in the form:
   - **Name**: Rule display name
   - **Pattern Type**: Choose matching strategy
   - **Pattern Value**: The pattern to match
   - **Weight**: 0-100 (importance score)
   - **Severity**: critical, high, medium, or low

**Via API:**
```bash
curl -X POST http://localhost:3000/api/custom-rules/proj_123 \
  -H "Authorization: Bearer your_token" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Admin Path Access",
    "pattern_type": "exact",
    "pattern_value": "/admin",
    "weight": 75,
    "severity": "high",
    "enabled": true
  }'
```

### 2. Test Your Rule

Before activation, test against real events:

```bash
curl -X POST http://localhost:3000/api/custom-rules/proj_123/rule_456/test \
  -H "Authorization: Bearer your_token" \
  -H "Content-Type: application/json" \
  -d '{
    "events": [
      {"path": "/admin", "status_code": 401},
      {"path": "/admin", "status_code": 403},
      {"path": "/user", "status_code": 200},
      {"path": "/admin", "status_code": 200}
    ]
  }'
```

**Response:**
```json
{
  "id": "result_789",
  "rule_id": "rule_456",
  "events_matched": 3,
  "true_positives": 2,
  "false_positives": 1,
  "accuracy": 0.667,
  "execution_time_ms": 12,
  "created_at": "2026-08-16T15:30:00Z"
}
```

### 3. Enable & Monitor

- Toggle "Enabled" to activate/deactivate
- Rules start evaluating immediately
- Matching events create alerts with rule-specified severity

## Pattern Types

### Exact Match
Matches exact string in request path.

**Example:**
```
Pattern: /admin
Matches: /admin
Doesn't match: /admin/users, /user/admin
```

**When to use:** API endpoints, specific paths you want to block

### Regular Expression
JavaScript regex pattern. Tested against request path.

**Example:**
```
Pattern: ^/api/v[0-9]+/admin
Matches: /api/v1/admin, /api/v2/admin, /api/v99/admin/users
Doesn't match: /api/admin, /api/vadmin
```

**When to use:** Patterns with wildcards, version prefixes, flexible matching

**Common patterns:**
```
/\.env        # Requests to .env file
/wp-admin|wordpress  # WordPress admin paths
/phpmyadmin   # phpMyAdmin access attempts
^/internal/   # Internal service paths
\?.*id=[0-9]+ # ID-based queries
```

### Threshold
Count-based detection: events exceed a limit.

**Format:** `fieldname:operator:value`

**Operators:** `>`, `>=`, `<`, `<=`, `=`

**Example:**
```
Pattern: ip:>10
Triggers: When 10+ events from same IP in time window
Use: Rate limiting, brute force with custom threshold
```

### Combination
Multiple conditions with AND/OR logic.

**Format:**
- AND: `field1=value1&field2=value2`
- OR: `field1=value1|field2=value2`

**Example:**
```
Pattern: method=POST&status_code=403
Matches: POST requests returning 403
Doesn't match: GET requests or status_code != 403
```

**Supported fields:**
- `method` (GET, POST, PUT, DELETE, etc.)
- `path` (request path)
- `status_code` (HTTP status)
- `ip` (source IP)

## Best Practices

### Rule Design
- **Start specific:** Exact > Regex > Combination
- **Test first:** Use test interface before enabling
- **Monitor accuracy:** Check true/false positive ratio
- **Iterate:** Adjust weight/pattern based on results

### Weight Assignment
- **80-100:** Critical threats requiring immediate attention
- **60-79:** High-risk patterns warranting investigation
- **40-59:** Medium-risk patterns to monitor
- **0-39:** Low-risk patterns or logging-only

### Avoid Over-Matching
```
❌ DON'T: /.*  (matches everything)
❌ DON'T: ^.*admin.*$  (too many false positives)
✓ DO: /admin/?$  (specific to admin path)
✓ DO: ^/api/v[0-9]+/admin  (version-aware)
```

### Rule Naming
Use descriptive names:
```
✓ "Database admin panel access"
✓ "Suspected SQL injection in search"
✗ "Rule 1"
✗ "Security thing"
```

## REST API Reference

### Create Rule
```
POST /api/custom-rules/:projectId
Authorization: Bearer <token>

{
  "name": string (required),
  "description": string (optional),
  "pattern_type": "exact" | "regex" | "threshold" | "combination" (required),
  "pattern_value": string (required),
  "weight": 0-100 (required),
  "severity": "critical" | "high" | "medium" | "low" (required),
  "enabled": boolean (default: true)
}

Response: 201 Created
{
  "id": "rule_...",
  "project_id": "proj_...",
  "name": "...",
  "version": 1,
  "enabled": true,
  "created_at": "2026-08-16T..."
}
```

### List Rules
```
GET /api/custom-rules/:projectId?enabledOnly=false
Authorization: Bearer <token>

Query params:
- enabledOnly: false (default) | true

Response: 200 OK
{
  "rules": [
    {
      "id": "rule_...",
      "name": "...",
      "pattern_type": "exact",
      "weight": 75,
      "severity": "high",
      "enabled": true,
      "version": 1,
      ...
    }
  ]
}
```

### Get Rule Detail
```
GET /api/custom-rules/:projectId/:ruleId
Authorization: Bearer <token>

Response: 200 OK
{
  "id": "rule_...",
  "name": "...",
  "description": "...",
  "pattern_type": "regex",
  "pattern_value": "/admin.*",
  "weight": 80,
  "severity": "critical",
  "enabled": true,
  "version": 3,
  "created_by": "user_...",
  "created_at": "2026-08-16T10:00:00Z",
  "updated_at": "2026-08-16T15:30:00Z"
}
```

### Update Rule
```
PATCH /api/custom-rules/:projectId/:ruleId
Authorization: Bearer <token>

{
  "name": string (optional),
  "description": string (optional),
  "pattern_value": string (optional),
  "weight": 0-100 (optional),
  "severity": string (optional),
  "enabled": boolean (optional)
}

Response: 200 OK
{
  "id": "rule_...",
  "version": 4,  // Incremented
  "updated_at": "2026-08-16T15:35:00Z",
  ...
}
```

### Delete Rule
```
DELETE /api/custom-rules/:projectId/:ruleId
Authorization: Bearer <token>

Response: 200 OK
{ "deleted": true }
```

### Test Rule
```
POST /api/custom-rules/:projectId/:ruleId/test
Authorization: Bearer <token>

{
  "events": [
    { "path": "/admin", "status_code": 401 },
    { "path": "/user", "status_code": 200 },
    ...
  ]
}

Limits:
- Max 10,000 events per test
- Execution time tracked

Response: 200 OK
{
  "id": "result_...",
  "rule_id": "rule_...",
  "test_run_id": "run_...",
  "events_matched": 2,
  "true_positives": 1,    // Matched AND status >= 400
  "false_positives": 1,   // Matched BUT status < 400
  "accuracy": 0.5,        // TP / (TP + FP)
  "execution_time_ms": 23,
  "created_at": "2026-08-16T..."
}
```

### Get Test Results
```
GET /api/custom-rules/:projectId/:ruleId/test-results?limit=10
Authorization: Bearer <token>

Response: 200 OK
{
  "results": [
    {
      "id": "result_...",
      "events_matched": 2,
      "accuracy": 0.667,
      "created_at": "2026-08-16T15:30:00Z"
    }
  ]
}
```

### Get Rule Versions
```
GET /api/custom-rules/:projectId/:ruleId/versions
Authorization: Bearer <token>

Response: 200 OK
{
  "versions": [
    {
      "id": "version_...",
      "version": 3,
      "pattern_value": "/admin.*",
      "weight": 80,
      "severity": "critical",
      "changes": {"weight": 80},
      "created_by": "user_...",
      "created_at": "2026-08-16T15:35:00Z"
    },
    {
      "id": "version_...",
      "version": 2,
      "pattern_value": "/admin",
      "weight": 75,
      "changes": {"pattern_value": "/admin.*"},
      ...
    }
  ]
}
```

## Examples

### Example 1: E-commerce Brute Force Protection
```json
{
  "name": "Excessive login attempts",
  "pattern_type": "exact",
  "pattern_value": "/login",
  "weight": 85,
  "severity": "high",
  "description": "Detects multiple failed login attempts"
}
```

### Example 2: API Version Mismatch Detection
```json
{
  "name": "Deprecated API access",
  "pattern_type": "regex",
  "pattern_value": "^/api/v[0-2]/",
  "weight": 60,
  "severity": "medium",
  "description": "Alerts on deprecated v0-v2 API usage"
}
```

### Example 3: Internal Service Access
```json
{
  "name": "Internal services exposed",
  "pattern_type": "exact",
  "pattern_value": "/internal/debug",
  "weight": 95,
  "severity": "critical",
  "description": "Should never be accessible externally"
}
```

### Example 4: Configuration File Leakage
```json
{
  "name": "Config file access attempts",
  "pattern_type": "regex",
  "pattern_value": "\\.(env|config|yaml|yml|json)$",
  "weight": 90,
  "severity": "critical",
  "description": "Attempts to access configuration files"
}
```

### Example 5: Suspicious HTTP Methods
```json
{
  "name": "TRACE/OPTIONS methods",
  "pattern_type": "combination",
  "pattern_value": "method=TRACE|method=OPTIONS",
  "weight": 70,
  "severity": "high",
  "description": "Rarely needed, often used for reconnaissance"
}
```

## Troubleshooting

### Rule Not Matching
1. Verify rule is **enabled** (toggle switch)
2. Test rule with sample events
3. Check pattern syntax for your pattern type
4. Verify field names match request fields

### High False Positive Rate
- **Too broad pattern:** Narrow the regex or use exact match
- **Wrong severity:** Lower severity if detecting normal traffic
- **Weight too high:** Decrease weight if rate-limiting needed

### Regex Performance Issues
- Avoid complex patterns with backtracking: `a*a*a*b`
- Use anchors: `^pattern$` instead of `pattern`
- Test complex regexes before enabling

### Memory Usage Growing
- Rules use regex caching (automatic)
- Disable unused rules
- Delete old test results if accumulating

## Limits & Quotas

| Limit | Value | Notes |
|-------|-------|-------|
| Rules per project | 100 | Increase via config if needed |
| Max pattern size | 10KB | Regex patterns should be smaller |
| Test events per run | 10,000 | Larger batches timeout |
| Rule evaluation latency | <10ms per rule | P95 target |
| Rule cache hit ratio | >99% | Regex patterns cached |
| Regex compilation timeout | 5 seconds | Prevents ReDoS attacks |

## Migration from Alert Rules

If you have existing alert rules:

1. **Document patterns:** List all regex patterns, paths
2. **Create custom rules:** Map each pattern to a custom rule
3. **Test accuracy:** Run test against historical events
4. **Enable gradual:** Roll out 25% at a time
5. **Monitor:** Check false positive rate for 24 hours
6. **Archive old rules:** After validation period

## Next Steps

### Enhance Your Rules
- Monitor accuracy trends
- Review test results weekly
- Adjust weights based on alert fatigue
- Share patterns across teams

### Automation
- Create rules via CI/CD
- Test rules automatically
- Deploy rules as code

### Advanced Features (Phase 13+)
- ML-based rule suggestions
- Rule marketplace (share patterns)
- A/B testing framework
- Performance profiling dashboard
- Audit logging per rule

## Support

- **Documentation:** See PHASE_12_CUSTOM_RULES.md (technical spec)
- **Examples:** Review Examples section above
- **Testing:** Use dashboard test interface
- **Performance:** Check execution_time_ms in test results

