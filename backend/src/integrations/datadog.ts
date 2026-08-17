import { sendWebhook } from './webhooks';

export interface DatadogConfig {
  api_key: string;
  app_key?: string;
  site?: string;
  tags?: string[];
}

export async function sendDatadogAlert(
  projectId: string,
  anomalyType: string,
  severity: 'critical' | 'high' | 'medium' | 'low',
  details: Record<string, any>
): Promise<void> {
  const severityMap: Record<string, string> = {
    critical: 'critical',
    high: 'error',
    medium: 'warning',
    low: 'info',
  };

  const priorityMap: Record<string, number> = {
    critical: 1,
    high: 2,
    medium: 3,
    low: 5,
  };

  const payload = {
    service: 'datadog',
    message_type: 'event',
    alert: {
      title: `Anomaly Detected: ${anomalyType}`,
      text: `An anomaly has been detected in project ${projectId}.\n\nAnomaly Type: ${anomalyType}\nSeverity: ${severity}\n\nView in Nettle: https://nettle.app/projects/${projectId}/analytics?anomaly=${anomalyType}`,
      alert_type: severityMap[severity],
      priority: priorityMap[severity],
      tags: [
        `project:${projectId}`,
        `anomaly_type:${anomalyType}`,
        `severity:${severity}`,
        'service:nettle',
      ],
      aggregation_key: `nettle-${projectId}-${anomalyType}`,
      date_happened: Math.floor(Date.now() / 1000),
      host: 'nettle-platform',
      source_type_name: 'nettle',
      related_event_id: details.event_id || undefined,
    },
    metrics: {
      anomaly_detected: {
        metric_name: 'nettle.anomaly.detected',
        points: [
          {
            timestamp: Math.floor(Date.now() / 1000),
            value: 1,
          },
        ],
        type: 'count',
        tags: [
          `project:${projectId}`,
          `anomaly_type:${anomalyType}`,
          `severity:${severity}`,
        ],
      },
    },
  };

  await sendWebhook(projectId, 'anomaly_alert', payload, 'datadog');
}

export async function sendDatadogMetric(
  projectId: string,
  metricName: string,
  value: number,
  tags?: Record<string, string>
): Promise<void> {
  const tagList = tags
    ? Object.entries(tags).map(([k, v]) => `${k}:${v}`)
    : [];

  const payload = {
    service: 'datadog',
    message_type: 'metric',
    metric: {
      metric_name: metricName,
      points: [
        {
          timestamp: Math.floor(Date.now() / 1000),
          value: value,
        },
      ],
      type: 'gauge',
      tags: [
        `project:${projectId}`,
        'service:nettle',
        ...tagList,
      ],
      host: 'nettle-platform',
    },
  };

  await sendWebhook(projectId, 'metric_event', payload, 'datadog');
}

export async function sendDatadogEvent(
  projectId: string,
  eventType: string,
  eventData: Record<string, any>,
  severity?: 'critical' | 'high' | 'medium' | 'low'
): Promise<void> {
  const severityMap: Record<string, string> = {
    critical: 'critical',
    high: 'error',
    medium: 'warning',
    low: 'info',
  };

  const payload = {
    service: 'datadog',
    message_type: 'event',
    event: {
      title: eventType,
      text: JSON.stringify(eventData, null, 2),
      alert_type: severity ? severityMap[severity] : 'info',
      tags: [
        `project:${projectId}`,
        `event_type:${eventType}`,
        'service:nettle',
      ],
      date_happened: Math.floor(Date.now() / 1000),
      host: 'nettle-platform',
      source_type_name: 'nettle',
    },
  };

  await sendWebhook(projectId, 'platform_event', payload, 'datadog');
}

export async function sendDatadogLog(
  projectId: string,
  message: string,
  level: 'debug' | 'info' | 'notice' | 'warning' | 'error' | 'critical',
  context?: Record<string, any>
): Promise<void> {
  const payload = {
    service: 'datadog',
    message_type: 'log',
    log: {
      message: message,
      level: level,
      logger: 'nettle',
      service: 'nettle',
      ddsource: 'nettle',
      ddtags: `project:${projectId},service:nettle`,
      timestamp: Math.floor(Date.now() / 1000) * 1000,
      context: context || {},
    },
  };

  await sendWebhook(projectId, 'log_event', payload, 'datadog');
}
