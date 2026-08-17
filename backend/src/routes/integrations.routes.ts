import { Router, Request, Response } from 'express';
import { requireAuth } from '../auth/middleware';
import { db, newId } from '../db/index';
import {
  createWebhookConfig,
  getWebhookConfigs,
  WebhookConfig,
  sendWebhook,
  WebhookEvent,
} from '../integrations/webhooks';

const router = Router();
router.use(requireAuth);

// Create webhook
router.post('/:projectId/webhooks', async (req: Request, res: Response) => {
  try {
    const { projectId } = req.params;
    const { service, webhook_url, event_types } = req.body;
    const userId = req.userId as string;

    // Verify project ownership
    const project = db.prepare('SELECT * FROM projects WHERE id = ? AND user_id = ?').get(projectId, userId) as any;
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
    const project = db.prepare('SELECT * FROM projects WHERE id = ? AND user_id = ?').get(projectId, userId) as any;
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
    const project = db.prepare('SELECT * FROM projects WHERE id = ? AND user_id = ?').get(projectId, userId) as any;
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
    const project = db.prepare('SELECT * FROM projects WHERE id = ? AND user_id = ?').get(projectId, userId) as any;
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    const webhook = db.prepare('SELECT * FROM webhooks WHERE id = ? AND project_id = ?').get(webhookId, projectId) as any;
    if (!webhook) {
      return res.status(404).json({ error: 'Webhook not found' });
    }

    const now = new Date().toISOString();
    const updates: any = { updated_at: now };

    if (webhook_url !== undefined) updates.webhook_url = webhook_url;
    if (event_types !== undefined) updates.event_types = JSON.stringify(event_types);
    if (is_active !== undefined) updates.is_active = is_active ? 1 : 0;

    const updateKeys = Object.keys(updates).map(k => `${k} = ?`).join(', ');
    const updateValues = Object.values(updates) as (string | number)[];

    db.prepare(`UPDATE webhooks SET ${updateKeys} WHERE id = ?`).run(...updateValues, webhookId);

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
    const project = db.prepare('SELECT * FROM projects WHERE id = ? AND user_id = ?').get(projectId, userId) as any;
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

// Test webhook delivery
router.post('/:projectId/webhooks/:webhookId/test', async (req: Request, res: Response) => {
  try {
    const { projectId, webhookId } = req.params;
    const userId = req.userId as string;

    // Verify project ownership
    const project = db.prepare('SELECT * FROM projects WHERE id = ? AND user_id = ?').get(projectId, userId) as any;
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
    const project = db.prepare('SELECT * FROM projects WHERE id = ? AND user_id = ?').get(projectId, userId) as any;
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

export default router;
