import { sendWebhook } from './webhooks';

export interface SlackConfig {
  webhook_url: string;
  channel?: string;
  username?: string;
  icon_emoji?: string;
}

export async function sendSlackAlert(
  projectId: string,
  anomalyType: string,
  severity: 'critical' | 'high' | 'medium' | 'low',
  details: Record<string, any>
): Promise<void> {
  const severityColors: Record<string, string> = {
    critical: '#cc0000',
    high: '#ff6600',
    medium: '#ff9900',
    low: '#0066cc',
  };

  const severityEmojis: Record<string, string> = {
    critical: '🚨',
    high: '⚠️',
    medium: '⚡',
    low: 'ℹ️',
  };

  const payload = {
    service: 'slack',
    message_type: 'anomaly_alert',
    attachments: [
      {
        color: severityColors[severity],
        title: `${severityEmojis[severity]} Anomaly Detected: ${anomalyType}`,
        title_link: `https://nettle.app/projects/${projectId}`,
        fields: [
          {
            title: 'Severity',
            value: severity.toUpperCase(),
            short: true,
          },
          {
            title: 'Type',
            value: anomalyType,
            short: true,
          },
          {
            title: 'Details',
            value: formatDetailsForSlack(details),
            short: false,
          },
        ],
        footer: 'Nettle Anomaly Detection',
        ts: Math.floor(Date.now() / 1000),
      },
    ],
  };

  await sendWebhook(projectId, 'anomaly_alert', payload, 'slack');
}

export async function sendSlackNotification(
  projectId: string,
  title: string,
  message: string,
  details?: Record<string, any>
): Promise<void> {
  const payload = {
    service: 'slack',
    message_type: 'notification',
    text: `${title}: ${message}`,
    attachments: [
      {
        color: '#0066cc',
        title,
        text: message,
        ...(details && {
          fields: Object.entries(details).map(([key, value]) => ({
            title: key,
            value: String(value),
            short: true,
          })),
        }),
        footer: 'Nettle',
        ts: Math.floor(Date.now() / 1000),
      },
    ],
  };

  await sendWebhook(projectId, 'notification', payload, 'slack');
}

function formatDetailsForSlack(details: Record<string, any>): string {
  return Object.entries(details)
    .map(([key, value]) => `*${key}:* ${formatValue(value)}`)
    .join('\n');
}

function formatValue(value: any): string {
  if (typeof value === 'object') {
    return JSON.stringify(value, null, 2);
  }
  return String(value);
}
