# Nettle Integrations Guide

Configure third-party services to receive real-time alerts and metrics from Nettle.

## Getting Started

1. Create a webhook in project settings: **Settings → Integrations → Add Webhook**
2. Select service (Slack, PagerDuty, Splunk, Datadog)
3. Provide service-specific credentials/URLs
4. Select event types to receive
5. Test delivery with **Send Test Event**

## Slack

### Setup

1. **Create Incoming Webhook** in Slack workspace
   - Go to https://api.slack.com/apps
   - Create New App → From Scratch
   - Name: "Nettle"
   - Select workspace
   - Enable Incoming Webhooks
   - Add New Webhook to Workspace
   - Copy Webhook URL

2. **In Nettle Dashboard**
   - Create webhook with service: `slack`
   - Paste webhook URL
   - Select events: `anomaly_alert`, `incident_alert`

### Message Format

```json
{
  "attachments": [
    {
      "color": "#cc0000",
      "title": "🚨 Anomaly Detected: traffic_spike",
      "title_link": "https://nettle.app/projects/xxx/analytics",
      "fields": [
        {
          "title": "Severity",
          "value": "CRITICAL",
          "short": true
        },
        {
          "title": "Type",
          "value": "traffic_spike",
          "short": true
        },
        {
          "title": "Details",
          "value": "Request rate increased by 3.2σ",
          "short": false
        }
      ],
      "footer": "Nettle Anomaly Detection"
    }
  ]
}
```

### Severity Colors

| Severity | Color | Emoji |
|---|---|---|
| Critical | #cc0000 | 🚨 |
| High | #ff6600 | ⚠️ |
| Medium | #ff9900 | ⚡ |
| Low | #0066cc | ℹ️ |

## PagerDuty

### Setup

1. **Get Routing Key**
   - Log in to PagerDuty
   - Go to Services → Create Service
   - Select "Event Rules Engines"
   - Copy Routing Key

2. **In Nettle Dashboard**
   - Create webhook with service: `pagerduty`
   - Paste routing key in webhook URL field
   - Select events: `incident_alert`, `incident_resolved`

### Incident Creation

Nettle automatically creates deduplicatable incidents:

```json
{
  "routing_key": "R1234...",
  "event_action": "trigger",
  "dedup_key": "nettle-project-uuid-anomaly-type-timestamp",
  "payload": {
    "summary": "Anomaly: traffic_spike (critical)",
    "severity": "critical",
    "source": "Nettle Anomaly Detection",
    "component": "project-uuid",
    "custom_details": {
      "anomaly_type": "traffic_spike",
      "project_id": "project-uuid"
    }
  }
}
```

### Incident Resolution

Use dedup key to resolve:

```json
{
  "routing_key": "R1234...",
  "event_action": "resolve",
  "dedup_key": "nettle-project-uuid-anomaly-type-xxx"
}
```

Incidents resolved when anomaly clears or manually closed in Nettle.

## Splunk

### Setup

1. **Enable HEC (HTTP Event Collector)**
   - Splunk Admin → Settings → Data Inputs
   - HTTP Event Collector → Add New
   - Name: "Nettle"
   - Leave defaults
   - Copy Token

2. **Get HEC URL**
   - Admin → Settings → Forwarding and Receiving
   - HTTP Event Collector → Cluster Info
   - HEC URL: `https://your-splunk-instance:8088`

3. **In Nettle Dashboard**
   - Create webhook with service: `splunk`
   - Webhook URL: `https://your-splunk-instance:8088/services/collector?token=TOKEN`
   - Select events: `anomaly_alert`, `metric_event`, `platform_event`

### Event Format

```json
{
  "event": {
    "event_type": "anomaly_detected",
    "anomaly_type": "traffic_spike",
    "project_id": "xxx",
    "severity_name": "critical",
    "severity_level": 10,
    "timestamp": "2024-01-01T00:00:00Z"
  },
  "source": "nettle_detection",
  "sourcetype": "nettle:anomaly",
  "host": "nettle-platform"
}
```

### Searching in Splunk

```spl
sourcetype=nettle:anomaly severity_level>=8
| stats count by anomaly_type
| timechart avg(severity_level) by anomaly_type
```

## Datadog

### Setup

1. **Get API Key**
   - Datadog → Organization Settings → API Keys
   - Create new API key
   - Name: "Nettle"
   - Copy key

2. **In Nettle Dashboard**
   - Create webhook with service: `datadog`
   - Webhook URL: `https://api.datadoghq.com/api/v1/events?api_key=YOUR_API_KEY`
   - Select events: `anomaly_alert`, `metric_event`, `platform_event`, `log_event`

### Event Format

```json
{
  "title": "Anomaly Detected: traffic_spike",
  "text": "Request rate increased by 3.2σ in project-xxx\n\nView in Nettle: https://nettle.app/projects/xxx/analytics",
  "alert_type": "critical",
  "priority": 1,
  "tags": [
    "project:xxx",
    "anomaly_type:traffic_spike",
    "severity:critical",
    "service:nettle"
  ],
  "aggregation_key": "nettle-xxx-traffic_spike"
}
```

### Metrics

```json
{
  "metric_name": "nettle.anomaly.detected",
  "points": [
    {
      "timestamp": 1234567890,
      "value": 1
    }
  ],
  "type": "count",
  "tags": [
    "project:xxx",
    "anomaly_type:traffic_spike",
    "severity:critical"
  ]
}
```

### Dashboards

Example dashboard query:

```
avg:nettle.anomaly.detected{service:nettle} by {project}
```

## Generic Webhooks

For unsupported services, use generic webhook:

1. Provide your endpoint URL
2. Nettle will POST events with HMAC-SHA256 signature
3. Verify signature header: `X-Nettle-Signature`

### Request Format

```bash
POST /your-endpoint HTTP/1.1
Content-Type: application/json
X-Nettle-Signature: sha256=hmac_hash
X-Nettle-Event-Type: anomaly_alert

{
  "id": "event-uuid",
  "timestamp": "2024-01-01T00:00:00Z",
  "event_type": "anomaly_alert",
  "data": {
    "project_id": "xxx",
    "anomaly_type": "traffic_spike",
    "severity": "critical",
    "details": { ... }
  }
}
```

### Verify Signature

```javascript
const crypto = require('crypto');

function verifySignature(body, signature) {
  const secret = process.env.NETTLE_WEBHOOK_SECRET;
  const computed = crypto
    .createHmac('sha256', secret)
    .update(body)
    .digest('hex');
  
  return computed === signature;
}
```

## Event Types

### anomaly_alert

Triggered when ML model detects anomalous behavior.

```json
{
  "anomaly_type": "traffic_spike|unusual_latency|error_rate_spike",
  "severity": "critical|high|medium|low",
  "z_score": 3.2,
  "details": {
    "metric": "request_rate",
    "baseline": 100,
    "current": 320,
    "timestamp": "2024-01-01T00:00:00Z"
  }
}
```

### incident_alert

Triggered when PagerDuty incident created (PagerDuty service only).

### scan_complete

Triggered when security scan finishes.

```json
{
  "scan_id": "scan-uuid",
  "status": "COMPLETED",
  "score": 87,
  "critical_count": 0,
  "caution_count": 3,
  "scanned_at": "2024-01-01T00:00:00Z"
}
```

### metric_event

Periodic metric submission (Splunk/Datadog).

### platform_event

General platform events (deployments, config changes).

### log_event

Structured logging (Datadog logs).

## Webhook Delivery

### Retry Logic

Failed deliveries retry automatically:

| Attempt | Delay | Total |
|---|---|---|
| 1 | Immediate | 0s |
| 2 | 1 second | 1s |
| 3 | 5 seconds | 6s |
| 4 | 30 seconds | 36s |
| 5 | 2 minutes | 156s |

After 5 failed attempts, webhook is disabled and alert sent to project owner.

### Status Tracking

View delivery status in **Webhooks → Event History**:
- **Pending** — Queued for delivery
- **Sent** — Successfully delivered
- **Failed** — All retries exhausted
- **Retrying** — Waiting for next retry

## Troubleshooting

### Webhook Not Triggering

1. Check webhook is enabled (toggle in settings)
2. Verify event types match what you configured
3. Send test event from webhook details page
4. Check event history for failures

### "Invalid Webhook URL"

1. Verify URL is https (http not supported)
2. Check service (Slack/PagerDuty/etc) is selected
3. Verify credentials/tokens are correct
4. Test with curl:
   ```bash
   curl -X POST https://your-url.com/webhook \
     -H "Content-Type: application/json" \
     -d '{"test": true}'
   ```

### High Failure Rate

1. Check service status (Slack, PagerDuty, etc)
2. Verify credentials still valid (tokens don't expire in Slack, but may in others)
3. Check firewall allows outbound to webhook URL
4. Review integration logs for error messages

### Missing Events

1. Confirm ML model detected anomalies (check Analytics dashboard)
2. Confirm event types are subscribed
3. Check webhook is active
4. Look at Event History to see if events were queued

## Best Practices

1. **Test webhook after setup** — Use "Send Test Event"
2. **Monitor delivery** — Check Event History regularly
3. **Set appropriate alert levels** — Don't send low-severity to PagerDuty
4. **Rotate secrets** — Change tokens quarterly
5. **Remove unused webhooks** — Clean up in settings
6. **Document mappings** — Which team owns which project
7. **Handle retries** — Webhook consumers should be idempotent

## Rate Limits

Webhook delivery is rate-limited:
- **1000 events per minute** per project
- **30 seconds per delivery** (timeout)
- **5 retries** maximum

If exceeding limits, contact support for higher tier.
