# Phase 12: Custom Detection Rules Engine

## Overview

Enable users to create, manage, and test custom detection rules without code changes. Extends the core Tier 2 detection pipeline with user-defined patterns.

## Scope

### 1. Custom Rule Definition
- Rule name, description, enabled/disabled
- Pattern matching: exact match, regex, threshold-based
- Signal metadata: weight (0-100), severity mapping, confidence formula
- Rule versioning with rollback support
- Test & validate before activation

### 2. Database Schema
- `custom_rules` table: project_id, name, pattern_type, pattern_value, weight, severity, enabled, created_at, updated_at, version
- `rule_versions` table: rule_id, version, pattern_value, weight, changes, created_by, created_at
- `rule_test_results` table: rule_id, test_run_id, events_matched, false_positives, true_positives, accuracy

### 3. REST API Endpoints
- POST /api/custom-rules (create rule)
- GET /api/custom-rules/:projectId (list rules)
- GET /api/custom-rules/:ruleId (get rule detail)
- PATCH /api/custom-rules/:ruleId (update rule)
- DELETE /api/custom-rules/:ruleId (delete rule)
- POST /api/custom-rules/:ruleId/test (test rule against sample events)
- POST /api/custom-rules/:ruleId/activate (activate version)
- GET /api/custom-rules/:ruleId/versions (list versions)

### 4. Rule Pattern Types
- **Exact Match**: Exact string in request field (method, path, ip)
- **Regex Pattern**: Regular expression on any field
- **Threshold**: Count-based (e.g., 10+ requests in 5min)
- **Combination**: Multiple conditions with AND/OR logic
- **ML-based**: Anomaly score (future phase)

### 5. Detection Pipeline Integration
- Detection runs built-in signals (existing 10) plus enabled custom rules
- Custom rule confidence calculated: (matched_events / total_events) × weight
- Custom signals merged into incident via risk scoring

### 6. UI Components
- Custom Rules page in dashboard
- Rule creation wizard with pattern builder
- Test interface with sample event selection
- Version history viewer
- Rule performance metrics (matches/day, accuracy, false positives)

### 7. Rule Execution & Performance
- Custom rules evaluated in parallel with built-in signals
- Cached compiled regex for performance
- Rate limiting per rule: max 10K rule evaluations/min per project
- Query optimization: index on (project_id, enabled, pattern_type)

## Implementation Tasks

### Task 1: Database Schema
- [ ] Create custom_rules table
- [ ] Create rule_versions table  
- [ ] Create rule_test_results table
- [ ] Add indexes for performance
- [ ] Migration script

### Task 2: Backend API
- [ ] Rule CRUD endpoints
- [ ] Pattern validation (regex syntax, field names)
- [ ] Version management
- [ ] Test execution endpoint
- [ ] Project ownership verification

### Task 3: Detection Pipeline Update
- [ ] Load custom rules at startup
- [ ] Integrate custom rule evaluation into detection.ts
- [ ] Handle rule failures gracefully (don't crash detection)
- [ ] Merge custom signals into risk scoring

### Task 4: Pattern Matching Engine
- [ ] Exact match evaluator
- [ ] Regex evaluator with caching
- [ ] Threshold evaluator (time-windowed counts)
- [ ] Combination evaluator (AND/OR logic)
- [ ] Performance profiling

### Task 5: Frontend UI
- [ ] Custom Rules list page
- [ ] Rule creation/edit modal
- [ ] Pattern builder interface
- [ ] Test interface with result visualization
- [ ] Version history view

### Task 6: Testing
- [ ] Unit tests for pattern matching
- [ ] Integration tests for API endpoints
- [ ] Security tests (injection, authorization)
- [ ] Performance tests (1000 rules evaluation)

### Task 7: Documentation
- [ ] PHASE_12_CUSTOM_RULES_GUIDE.md (user guide)
- [ ] API documentation for rule endpoints
- [ ] Pattern syntax reference
- [ ] Examples and templates

## Architecture

```
Event → Built-in Signals (10) → Custom Rules (N) → Risk Scoring → Incident
                ↓                    ↓
              [signals]           [custom_signals]
                ↓                    ↓
                └────────┬──────────┘
                         ↓
                   Aggregate Confidence
                   (weighted sum)
                         ↓
                   Severity Classification
                         ↓
                   Create/Update Incident
```

## Success Criteria

- ✓ Users create custom rules without code
- ✓ Rules execute in <10ms per event
- ✓ Rules can be versioned and rolled back
- ✓ Test interface validates rules before activation
- ✓ Rules inherit project-scoped isolation
- ✓ 40+ test cases (unit + integration + security)
- ✓ Full documentation with examples

## Metrics

| Metric | Target |
|--------|--------|
| Rule creation latency | < 1s |
| Rule evaluation latency | < 10ms per rule |
| Rule execution accuracy | >95% |
| Regex compilation caching | >99% hit ratio |
| Max rules per project | 100 (configurable) |
| Test execution time | < 5s for 1000 events |

## Timeline

- Backend API & DB: 2-3 hours
- Pattern matching engine: 1-2 hours
- Detection pipeline integration: 1 hour
- Frontend UI: 2-3 hours
- Testing & polish: 2 hours

**Estimated Total: 8-11 hours of development**

## Optional Enhancements (Phase 12+)

- ML-based rule suggestions (analyzing false positives)
- Rule marketplace (share rules between projects)
- A/B testing framework (test new rules in shadow mode)
- Audit logging per rule (what matched, when, why)
- Rule performance dashboard (detection stats per rule)
- Regex performance analyzer (warn on slow patterns)

## Dependencies

- Nettle Tier 2 (main branch) - ✓ Merged
- PostgreSQL with custom_rules schema
- Redis for caching compiled rules
- Existing project ownership model
- Existing risk scoring engine

## Compatibility

- ✓ Backward compatible (custom rules optional)
- ✓ No changes to existing API contracts
- ✓ Existing incidents unaffected
- ✓ Can disable custom rules per project via config
