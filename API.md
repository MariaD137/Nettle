# Nettle API Reference

Base URL: `https://api.nettle.app`  
Version: `1.0`

## Authentication

All endpoints require a Bearer token in the `Authorization` header:

```bash
Authorization: Bearer YOUR_API_TOKEN
```

Tokens are issued during signup and can be regenerated in account settings.

## Rate Limiting

Rate limits applied per endpoint:

| Endpoint | Limit | Window |
|---|---|---|
| `/api/scans` (POST) | 30 requests | 1 minute |
| `/api/events` | 100 requests | 5 minutes |
| `/api/badge` | 100 requests | 5 minutes |
| All other | 500 requests | 1 minute |

Response headers:
- `Retry-After`: seconds until rate limit resets
- Returns `429 Too Many Requests` when exceeded

## Endpoints

### Authentication

#### POST /api/auth/signup
Create a new account.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "secure-password"
}
```

**Response:**
```json
{
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "plan": "free",
    "created_at": "2024-01-01T00:00:00Z"
  },
  "token": "session-token"
}
```

#### POST /api/auth/login
Authenticate and get session token.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "secure-password"
}
```

**Response:**
```json
{
  "token": "session-token",
  "user": { ... }
}
```

#### GET /api/auth/me
Get current user profile.

**Response:**
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "plan": "free",
  "subscription_status": "active",
  "created_at": "2024-01-01T00:00:00Z"
}
```

### Projects

#### GET /api/projects
List all projects for the user.

**Response:**
```json
{
  "projects": [
    {
      "id": "uuid",
      "name": "My App",
      "url": "https://myapp.com",
      "environment": "production",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

#### POST /api/projects
Create a new project.

**Request:**
```json
{
  "name": "My App",
  "url": "https://myapp.com",
  "description": "Production application",
  "environment": "production"
}
```

**Response:**
```json
{
  "id": "uuid",
  "name": "My App",
  "api_key": "nettle_xxxxx",
  "created_at": "2024-01-01T00:00:00Z"
}
```

#### GET /api/projects/{projectId}
Get project details.

**Response:**
```json
{
  "id": "uuid",
  "name": "My App",
  "url": "https://myapp.com",
  "api_key": "nettle_xxxxx",
  "environment": "production",
  "created_at": "2024-01-01T00:00:00Z"
}
```

#### PATCH /api/projects/{projectId}
Update project settings.

**Request:**
```json
{
  "name": "Updated Name",
  "url": "https://newurl.com"
}
```

#### DELETE /api/projects/{projectId}
Delete a project and all its data.

### Scans

#### POST /api/scans
Upload code for security scanning.

**Request (multipart/form-data):**
- `file`: ZIP archive of source code
- `projectId`: (optional) Associate with project

**Response:**
```json
{
  "id": "scan-uuid",
  "status": "SCANNING",
  "score": null,
  "created_at": "2024-01-01T00:00:00Z"
}
```

#### GET /api/scans/{scanId}
Get scan results.

**Response:**
```json
{
  "id": "scan-uuid",
  "status": "COMPLETED",
  "score": 87,
  "critical_count": 0,
  "caution_count": 3,
  "clear_count": 12,
  "report_json": { ... },
  "scanned_at": "2024-01-01T00:00:00Z"
}
```

#### GET /api/projects/{projectId}/scans
List scans for a project.

**Query Parameters:**
- `limit`: default 50, max 200
- `offset`: for pagination
- `status`: filter by SCANNING, COMPLETED, FAILED

**Response:**
```json
{
  "scans": [ ... ],
  "total": 42,
  "offset": 0,
  "limit": 50
}
```

#### GET /api/scans/{scanId}/findings
Get individual findings from a scan.

**Response:**
```json
{
  "findings": [
    {
      "id": "finding-uuid",
      "type": "hardcoded_secret",
      "severity": "critical",
      "file": "src/config.ts",
      "line": 15,
      "message": "AWS Access Key found",
      "ruleId": "semgrep.aws.secrets.hardcoded-access-key",
      "confidence": "HIGH",
      "evidence": "AKIA*** (redacted)",
      "remediation": "Remove credential and rotate key"
    }
  ]
}
```

### Webhooks

#### POST /api/projects/{projectId}/webhooks/
Create a webhook for event notifications.

**Request:**
```json
{
  "service": "slack",
  "webhook_url": "https://hooks.slack.com/services/...",
  "event_types": ["anomaly_alert", "incident_alert"]
}
```

**Response:**
```json
{
  "id": "webhook-uuid",
  "project_id": "project-uuid",
  "service": "slack",
  "webhook_url": "https://hooks.slack.com/services/...",
  "is_active": true,
  "event_types": ["anomaly_alert", "incident_alert"],
  "created_at": "2024-01-01T00:00:00Z"
}
```

#### GET /api/projects/{projectId}/webhooks/
List project webhooks.

**Response:**
```json
[
  {
    "id": "webhook-uuid",
    "service": "slack",
    "webhook_url": "https://...",
    "is_active": true,
    "event_types": [ ... ]
  },
  {
    "id": "webhook-uuid-2",
    "service": "pagerduty",
    "webhook_url": "https://...",
    "is_active": true,
    "event_types": [ ... ]
  }
]
```

#### GET /api/projects/{projectId}/webhooks/{webhookId}
Get specific webhook details.

#### PATCH /api/projects/{projectId}/webhooks/{webhookId}
Update webhook configuration.

**Request:**
```json
{
  "webhook_url": "https://new-url.com/webhook",
  "is_active": false,
  "event_types": ["anomaly_alert"]
}
```

#### DELETE /api/projects/{projectId}/webhooks/{webhookId}
Delete a webhook.

#### POST /api/projects/{projectId}/webhooks/{webhookId}/test
Send a test event to the webhook.

**Response:**
```json
{
  "message": "Test webhook sent successfully"
}
```

#### GET /api/projects/{projectId}/webhooks/{webhookId}/events
Get webhook delivery history.

**Query Parameters:**
- `limit`: default 50

**Response:**
```json
[
  {
    "id": "event-uuid",
    "webhook_id": "webhook-uuid",
    "event_type": "anomaly_alert",
    "payload": { ... },
    "status": "sent",
    "attempt_count": 1,
    "created_at": "2024-01-01T00:00:00Z",
    "sent_at": "2024-01-01T00:00:05Z"
  }
]
```

### Analytics

#### GET /api/analytics/dashboard
Get analytics dashboard data.

**Response:**
```json
{
  "project_id": "project-uuid",
  "baseline_stats": {
    "request_rate": { "mean": 100, "std_dev": 15 },
    "error_rate": { "mean": 0.02, "std_dev": 0.005 }
  },
  "anomalies": [
    {
      "id": "anomaly-uuid",
      "anomaly_type": "traffic_spike",
      "severity": "high",
      "z_score": 3.2,
      "timestamp": "2024-01-01T00:00:00Z"
    }
  ]
}
```

#### GET /api/analytics/baselines
Get baseline metrics for a project.

**Query Parameters:**
- `metric`: metric_name to filter
- `period`: daily, hourly, weekly

#### POST /api/analytics/calculate-baseline
Recalculate baselines from raw data.

**Request:**
```json
{
  "start_date": "2024-01-01",
  "end_date": "2024-01-31"
}
```

### Custom Rules

#### GET /api/custom-rules
List custom detection rules.

**Response:**
```json
[
  {
    "id": "rule-uuid",
    "name": "Detect Stripe keys",
    "pattern_type": "regex",
    "pattern_value": "sk_live_[a-zA-Z0-9]{20,}",
    "severity": "critical",
    "weight": 10,
    "enabled": true,
    "created_at": "2024-01-01T00:00:00Z"
  }
]
```

#### POST /api/custom-rules
Create a new custom rule.

**Request:**
```json
{
  "name": "Detect API keys",
  "pattern_type": "regex",
  "pattern_value": "api_key[=:]\\s*['\\\"]([a-zA-Z0-9_-]+)['\\\"]",
  "severity": "critical",
  "weight": 10
}
```

#### PATCH /api/custom-rules/{ruleId}
Update a custom rule.

#### DELETE /api/custom-rules/{ruleId}
Delete a custom rule.

#### POST /api/custom-rules/{ruleId}/test
Test a rule against sample code.

**Request:**
```json
{
  "sample_code": "const API_KEY = 'sk_test_abc123';"
}
```

**Response:**
```json
{
  "matched": true,
  "matches": [
    {
      "line": 1,
      "column": 20,
      "text": "sk_test_abc123"
    }
  ]
}
```

### Public Endpoints

#### GET /api/badge/{projectId}.svg
Get project badge (no auth required).

Returns SVG badge showing latest scan score.

#### POST /api/events
Ingest security events (no auth required).

**Request:**
```json
{
  "project_id": "project-uuid",
  "event_type": "failed_auth",
  "ip": "192.168.1.1",
  "user_agent": "Mozilla/...",
  "path": "/admin",
  "status_code": 401
}
```

## Errors

All errors return JSON with this structure:

```json
{
  "error": "Human-readable error message",
  "code": "error_code",
  "details": { ... }
}
```

**Common status codes:**
- `400` — Bad Request (validation error)
- `401` — Unauthorized (missing/invalid token)
- `403` — Forbidden (insufficient permissions)
- `404` — Not Found
- `429` — Rate Limit Exceeded
- `500` — Internal Server Error

## Webhook Events

Webhook payload structure:

```json
{
  "id": "event-uuid",
  "timestamp": "2024-01-01T00:00:00Z",
  "event_type": "anomaly_alert",
  "data": {
    "project_id": "project-uuid",
    "anomaly_type": "traffic_spike",
    "severity": "high",
    "details": { ... }
  }
}
```

**Event Types:**
- `anomaly_alert` — ML model detected anomaly
- `incident_alert` — PagerDuty incident created
- `scan_complete` — Scan finished
- `test_event` — Webhook test delivery
