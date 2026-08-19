import { Router, Request, Response } from 'express';
import { requireAuth } from '../auth/middleware';
import { db, newId } from '../db/index';
import { getOwnedProject } from '../patrol/projectAccess';
import { webhookRateLimit } from '../middleware/rateLimit';
import {
  createWebhookConfig,
  getWebhookConfigs,
  WebhookConfig,
  sendWebhook,
  WebhookEvent,
} from '../integrations/webhooks';
import {
  createNotificationChannel,
  getNotificationChannels,
  updateNotificationChannel,
  deleteNotificationChannel,
  NotificationChannelType,
} from '../patrol/notificationChannels';

const router = Router();
router.use(requireAuth);

// Create webhook
router.post('/:projectId/webhooks', async (req: Request, res: Response) => {
  try {
    const { projectId } = req.params;
    const { service, webhook_url, event_types } = req.body;
    const userId = req.userId as string;

    // Verify project ownership
    const project = getOwnedProject(projectId, userId);
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    // Validate input
    if (!service || !webhook_url || !event_types || !Array.isArray(event_types)) {
      return res.status(400).json({ error: 'Missing or invalid required fields' });
    }

    const validServices = ['slack', 'pagerduty', 'splunk', 'datadog', 'generic'];
    if (!validServices.includes(service)) {
      return res.status(400).json({ error: `Invalid service: ${service}` });
    }

    // Create webhook config
    const webhook = createWebhookConfig(projectId, service, webhook_url, event_types);
    res.status(201).json(webhook);
  } catch (error) {
    console.error('Error creating webhook:', error);
    res.status(500).json({ error: 'Failed to create webhook' });
  }
});

// List webhooks for project
router.get('/:projectId/webhooks', async (req: Request, res: Response) => {
  try {
    const { projectId } = req.params;
    const userId = req.userId as string;

    // Verify project ownership
    const project = getOwnedProject(projectId, userId);
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    const webhooks = getWebhookConfigs(projectId);
    res.json(webhooks);
  } catch (error) {
    console.error('Error listing webhooks:', error);
    res.status(500).json({ error: 'Failed to list webhooks' });
  }
});

// Get specific webhook
router.get('/:projectId/webhooks/:webhookId', async (req: Request, res: Response) => {
  try {
    const { projectId, webhookId } = req.params;
    const userId = req.userId as string;

    // Verify project ownership
    const project = getOwnedProject(projectId, userId);
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    const webhook = db.prepare('SELECT * FROM webhooks WHERE id = ? AND project_id = ?').get(webhookId, projectId) as any;
    if (!webhook) {
      return res.status(404).json({ error: 'Webhook not found' });
    }

    const result: WebhookConfig = {
      id: webhook.id,
      project_id: webhook.project_id,
      service: webhook.service,
      webhook_url: webhook.webhook_url,
      is_active: webhook.is_active === 1,
      event_types: JSON.parse(webhook.event_types || '[]'),
      created_at: webhook.created_at,
      updated_at: webhook.updated_at,
    };

    res.json(result);
  } catch (error) {
    console.error('Error retrieving webhook:', error);
    res.status(500).json({ error: 'Failed to retrieve webhook' });
  }
});

// Update webhook
router.patch('/:projectId/webhooks/:webhookId', async (req: Request, res: Response) => {
  try {
    const { projectId, webhookId } = req.params;
    const { webhook_url, event_types, is_active } = req.body;
    const userId = req.userId as string;

    // Verify project ownership
    const project = getOwnedProject(projectId, userId);
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    const webhook = db.prepare('SELECT * FROM webhooks WHERE id = ? AND project_id = ?').get(webhookId, projectId) as any;
    if (!webhook) {
      return res.status(404).json({ error: 'Webhook not found' });
    }

    const now = new Date().toISOString();

    // Fixed column list — never built from request-controlled keys, so
    // there's no way for a caller to inject arbitrary column names here.
    db.prepare(
      'UPDATE webhooks SET webhook_url = ?, event_types = ?, is_active = ?, updated_at = ? WHERE id = ?'
    ).run(
      webhook_url !== undefined ? webhook_url : webhook.webhook_url,
      event_types !== undefined ? JSON.stringify(event_types) : webhook.event_types,
      is_active !== undefined ? (is_active ? 1 : 0) : webhook.is_active,
      now,
      webhookId
    );

    const updatedWebhook = db.prepare('SELECT * FROM webhooks WHERE id = ?').get(webhookId) as any;
    const result: WebhookConfig = {
      id: updatedWebhook.id,
      project_id: updatedWebhook.project_id,
      service: updatedWebhook.service,
      webhook_url: updatedWebhook.webhook_url,
      is_active: updatedWebhook.is_active === 1,
      event_types: JSON.parse(updatedWebhook.event_types),
      created_at: updatedWebhook.created_at,
      updated_at: updatedWebhook.updated_at,
    };

    res.json(result);
  } catch (error) {
    console.error('Error updating webhook:', error);
    res.status(500).json({ error: 'Failed to update webhook' });
  }
});

// Delete webhook
router.delete('/:projectId/webhooks/:webhookId', async (req: Request, res: Response) => {
  try {
    const { projectId, webhookId } = req.params;
    const userId = req.userId as string;

    // Verify project ownership
    const project = getOwnedProject(projectId, userId);
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    const webhook = db.prepare('SELECT * FROM webhooks WHERE id = ? AND project_id = ?').get(webhookId, projectId) as any;
    if (!webhook) {
      return res.status(404).json({ error: 'Webhook not found' });
    }

    db.prepare('DELETE FROM webhook_events WHERE webhook_id = ?').run(webhookId);
    db.prepare('DELETE FROM webhooks WHERE id = ?').run(webhookId);

    res.status(204).send();
  } catch (error) {
    console.error('Error deleting webhook:', error);
    res.status(500).json({ error: 'Failed to delete webhook' });
  }
});

// Test webhook delivery. The only route in this file that actually
// triggers a real outbound HTTP request (see integrations/webhooks.ts) —
// webhookRateLimit was defined but never wired into any real request path
// until now; every other route here just reads/writes config and is
// already covered by the app-wide apiRateLimit.
router.post('/:projectId/webhooks/:webhookId/test', webhookRateLimit, async (req: Request, res: Response) => {
  try {
    const { projectId, webhookId } = req.params;
    const userId = req.userId as string;

    // Verify project ownership
    const project = getOwnedProject(projectId, userId);
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    const webhook = db.prepare('SELECT * FROM webhooks WHERE id = ? AND project_id = ?').get(webhookId, projectId) as any;
    if (!webhook) {
      return res.status(404).json({ error: 'Webhook not found' });
    }

    // Send test payload
    const testPayload = {
      service: webhook.service,
      message_type: 'test_event',
      test: true,
      timestamp: new Date().toISOString(),
      project_id: projectId,
    };

    await sendWebhook(projectId, 'test_event', testPayload);

    res.json({ message: 'Test webhook sent successfully' });
  } catch (error) {
    console.error('Error testing webhook:', error);
    res.status(500).json({ error: 'Failed to send test webhook' });
  }
});

// Get webhook event delivery history
router.get('/:projectId/webhooks/:webhookId/events', async (req: Request, res: Response) => {
  try {
    const { projectId, webhookId } = req.params;
    const userId = req.userId as string;
    const limit = parseInt(req.query.limit as string) || 50;

    // Verify project ownership
    const project = getOwnedProject(projectId, userId);
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    const webhook = db.prepare('SELECT * FROM webhooks WHERE id = ? AND project_id = ?').get(webhookId, projectId) as any;
    if (!webhook) {
      return res.status(404).json({ error: 'Webhook not found' });
    }

    const events = db
      .prepare('SELECT * FROM webhook_events WHERE webhook_id = ? ORDER BY created_at DESC LIMIT ?')
      .all(webhookId, limit) as unknown as WebhookEvent[];

    const result = events.map(e => ({
      ...e,
      payload: JSON.parse(e.payload as any),
    }));

    res.json(result);
  } catch (error) {
    console.error('Error fetching webhook events:', error);
    res.status(500).json({ error: 'Failed to fetch webhook events' });
  }
});

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const E164_PATTERN = /^\+[1-9]\d{1,14}$/;
const VALID_CHANNELS: NotificationChannelType[] = ['email', 'sms'];

function isValidDestination(channel: NotificationChannelType, destination: string): boolean {
  return channel === 'email' ? EMAIL_PATTERN.test(destination) : E164_PATTERN.test(destination);
}

// Serialized the same snake_case shape as the webhook endpoints above, for
// consistency within this route file — createNotificationChannel /
// updateNotificationChannel return the camelCase NotificationChannel type
// used internally (scans.ts, alerts.ts, digest.ts), but the wire format
// here matches its sibling endpoints.
function serializeChannel(channel: ReturnType<typeof createNotificationChannel>) {
  return {
    id: channel.id,
    project_id: channel.projectId,
    channel: channel.channel,
    destination: channel.destination,
    is_active: channel.isActive,
    event_types: channel.eventTypes,
    created_at: channel.createdAt,
    updated_at: channel.updatedAt,
  };
}

// Create notification channel
router.post('/:projectId/notification-channels', async (req: Request, res: Response) => {
  try {
    const { projectId } = req.params;
    const { channel, destination, event_types } = req.body;
    const userId = req.userId as string;

    const project = getOwnedProject(projectId, userId);
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    if (!channel || !destination || !event_types || !Array.isArray(event_types)) {
      return res.status(400).json({ error: 'Missing or invalid required fields' });
    }
    if (!VALID_CHANNELS.includes(channel)) {
      return res.status(400).json({ error: `Invalid channel: ${channel}` });
    }
    if (!isValidDestination(channel, destination)) {
      return res.status(400).json({
        error: channel === 'email' ? 'destination must be a valid email address' : 'destination must be a valid E.164 phone number, e.g. +15551234567',
      });
    }

    const created = createNotificationChannel(projectId, channel, destination, event_types);
    res.status(201).json(serializeChannel(created));
  } catch (error) {
    console.error('Error creating notification channel:', error);
    res.status(500).json({ error: 'Failed to create notification channel' });
  }
});

// List notification channels for project
router.get('/:projectId/notification-channels', async (req: Request, res: Response) => {
  try {
    const { projectId } = req.params;
    const userId = req.userId as string;

    const project = getOwnedProject(projectId, userId);
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    res.json(getNotificationChannels(projectId).map(serializeChannel));
  } catch (error) {
    console.error('Error listing notification channels:', error);
    res.status(500).json({ error: 'Failed to list notification channels' });
  }
});

// Update notification channel
router.patch('/:projectId/notification-channels/:channelId', async (req: Request, res: Response) => {
  try {
    const { projectId, channelId } = req.params;
    const { destination, event_types, is_active } = req.body;
    const userId = req.userId as string;

    const project = getOwnedProject(projectId, userId);
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    const existing = db.prepare('SELECT * FROM notification_channels WHERE id = ? AND project_id = ?').get(channelId, projectId) as any;
    if (!existing) {
      return res.status(404).json({ error: 'Notification channel not found' });
    }

    if (destination !== undefined && !isValidDestination(existing.channel, destination)) {
      return res.status(400).json({
        error: existing.channel === 'email' ? 'destination must be a valid email address' : 'destination must be a valid E.164 phone number, e.g. +15551234567',
      });
    }

    const updated = updateNotificationChannel(channelId, {
      destination,
      eventTypes: event_types,
      isActive: is_active,
    });
    res.json(serializeChannel(updated!));
  } catch (error) {
    console.error('Error updating notification channel:', error);
    res.status(500).json({ error: 'Failed to update notification channel' });
  }
});

// Delete notification channel
router.delete('/:projectId/notification-channels/:channelId', async (req: Request, res: Response) => {
  try {
    const { projectId, channelId } = req.params;
    const userId = req.userId as string;

    const project = getOwnedProject(projectId, userId);
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    const existing = db.prepare('SELECT * FROM notification_channels WHERE id = ? AND project_id = ?').get(channelId, projectId) as any;
    if (!existing) {
      return res.status(404).json({ error: 'Notification channel not found' });
    }

    deleteNotificationChannel(channelId);
    res.status(204).send();
  } catch (error) {
    console.error('Error deleting notification channel:', error);
    res.status(500).json({ error: 'Failed to delete notification channel' });
  }
});

export default router;
