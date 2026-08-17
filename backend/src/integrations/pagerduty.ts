import { sendWebhook } from './webhooks';

export interface PagerDutyConfig {
  integration_key: string;
  service_id?: string;
}

export async function sendPagerDutyAlert(
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

  const payload = {
    service: 'pagerduty',
    message_type: 'incident',
    routing_key: details.routing_key || process.env.PAGERDUTY_ROUTING_KEY,
    event_action: 'trigger',
    dedup_key: `nettle-${projectId}-${anomalyType}-${Date.now()}`,
    payload: {
      summary: `Anomaly: ${anomalyType} (${severity})`,
      severity: severityMap[severity],
      source: 'Nettle Anomaly Detection',
      component: projectId,
      custom_details: {
        anomaly_type: anomalyType,
        project_id: projectId,
        timestamp: new Date().toISOString(),
        ...details,
      },
    },
    client: 'Nettle',
    client_url: `https://nettle.app/projects/${projectId}`,
    links: [
      {
        href: `https://nettle.app/projects/${projectId}/analytics`,
        text: 'View Analytics',
      },
    ],
  };

  await sendWebhook(projectId, 'incident_alert', payload);
}

export async function resolvePagerDutyIncident(
  projectId: string,
  dedup_key: string
): Promise<void> {
  const payload = {
    service: 'pagerduty',
    message_type: 'incident_resolved',
    routing_key: process.env.PAGERDUTY_ROUTING_KEY,
    event_action: 'resolve',
    dedup_key,
  };

  await sendWebhook(projectId, 'incident_resolved', payload);
}
