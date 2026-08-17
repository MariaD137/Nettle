import { sendWebhook } from './webhooks';

export interface SplunkConfig {
  hec_url: string;
  hec_token: string;
  index?: string;
  source?: string;
}

export async function sendSplunkAlert(
  projectId: string,
  anomalyType: string,
  severity: 'critical' | 'high' | 'medium' | 'low',
  details: Record<string, any>
): Promise<void> {
  const severityMap: Record<string, number> = {
    critical: 10,
    high: 8,
    medium: 6,
    low: 4,
  };

  const payload = {
    service: 'splunk',
    message_type: 'anomaly_event',
    event: {
      sourcetype: 'nettle:anomaly',
      source: 'nettle_detection',
      host: 'nettle-platform',
      time: Math.floor(Date.now() / 1000),
      event: {
        event_type: 'anomaly_detected',
        anomaly_type: anomalyType,
        project_id: projectId,
        severity_name: severity,
        severity_level: severityMap[severity],
        timestamp: new Date().toISOString(),
        details: details,
        alert_url: `https://nettle.app/projects/${projectId}/analytics?anomaly=${anomalyType}`,
      },
      fields: {
        project_id: projectId,
        anomaly_type: anomalyType,
        severity: severity,
      },
    },
  };

  await sendWebhook(projectId, 'anomaly_alert', payload, 'splunk');
}

export async function sendSplunkMetric(
  projectId: string,
  metricName: string,
  value: number,
  tags?: Record<string, string>
): Promise<void> {
  const payload = {
    service: 'splunk',
    message_type: 'metric',
    metric: {
      metric_name: metricName,
      _value: value,
      _time: Math.floor(Date.now() / 1000),
      sourcetype: 'nettle:metric',
      host: 'nettle-platform',
      fields: {
        project_id: projectId,
        ...tags,
      },
    },
  };

  await sendWebhook(projectId, 'metric_event', payload, 'splunk');
}

export async function sendSplunkEvent(
  projectId: string,
  eventType: string,
  eventData: Record<string, any>
): Promise<void> {
  const payload = {
    service: 'splunk',
    message_type: 'event',
    event: {
      event_type: eventType,
      project_id: projectId,
      timestamp: new Date().toISOString(),
      data: eventData,
      sourcetype: 'nettle:event',
      source: 'nettle_platform',
      host: 'nettle-platform',
    },
  };

  await sendWebhook(projectId, 'platform_event', payload, 'splunk');
}
