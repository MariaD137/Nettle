import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { api, ApiError, WEBHOOK_EVENT_TYPES, type Webhook, type WebhookService } from '../api';
import './IntegrationsPage.css';

const SERVICES: WebhookService[] = ['slack', 'pagerduty', 'splunk', 'datadog', 'generic'];

export function IntegrationsPage() {
  const { projectId } = useParams<{ projectId: string }>();
  const [webhooks, setWebhooks] = useState<Webhook[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [testMessage, setTestMessage] = useState<Record<string, string>>({});

  useEffect(() => {
    if (projectId) loadWebhooks();
  }, [projectId]);

  async function loadWebhooks() {
    if (!projectId) return;
    try {
      setLoading(true);
      setWebhooks(await api.listWebhooks(projectId));
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Error loading webhooks');
    } finally {
      setLoading(false);
    }
  }

  async function deleteWebhook(webhookId: string) {
    if (!projectId) return;
    if (confirm('Are you sure you want to remove this webhook?')) {
      try {
        await api.deleteWebhook(projectId, webhookId);
        setWebhooks(webhooks.filter((w) => w.id !== webhookId));
      } catch (err) {
        setError(err instanceof ApiError ? err.message : 'Failed to remove webhook');
      }
    }
  }

  async function toggleActive(webhook: Webhook) {
    if (!projectId) return;
    try {
      await api.updateWebhook(projectId, webhook.id, { is_active: !webhook.is_active });
      loadWebhooks();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to update webhook');
    }
  }

  async function sendTest(webhookId: string) {
    if (!projectId) return;
    setTestMessage((m) => ({ ...m, [webhookId]: 'Sending…' }));
    try {
      const { message } = await api.testWebhook(projectId, webhookId);
      setTestMessage((m) => ({ ...m, [webhookId]: message }));
    } catch (err) {
      setTestMessage((m) => ({ ...m, [webhookId]: err instanceof ApiError ? err.message : 'Test failed' }));
    }
  }

  if (loading) return <div className="loading">Loading integrations...</div>;

  return (
    <div className="integrations-page">
      <div className="page-header">
        <h1>Integrations</h1>
        <button className="btn-primary" onClick={() => setShowForm(true)}>
          + Add webhook
        </button>
      </div>

      <p className="page-description">
        Send scan and alert events to Slack, PagerDuty, Splunk, Datadog, or any generic HTTPS endpoint. Each
        delivery is HMAC-signed and retried on transient failures.
      </p>

      {error && <div className="error-message">{error}</div>}

      {showForm && (
        <WebhookForm
          projectId={projectId!}
          onSave={() => {
            setShowForm(false);
            loadWebhooks();
          }}
          onCancel={() => setShowForm(false)}
        />
      )}

      <div className="webhooks-list">
        {webhooks.length === 0 ? (
          <div className="empty-state">
            <p>No webhooks configured yet. Add one to get notified when scans finish or alerts fire.</p>
          </div>
        ) : (
          webhooks.map((webhook) => (
            <div key={webhook.id} className="webhook-card">
              <div className="webhook-header">
                <div>
                  <h3>{webhook.service}</h3>
                  <p className="webhook-url">{webhook.webhook_url}</p>
                </div>
                <div className="webhook-actions">
                  <label className="toggle">
                    <input type="checkbox" checked={webhook.is_active} onChange={() => toggleActive(webhook)} />
                    <span>{webhook.is_active ? 'Active' : 'Paused'}</span>
                  </label>
                  <button className="btn-secondary" onClick={() => sendTest(webhook.id)}>
                    Send test
                  </button>
                  <button className="btn-danger" onClick={() => deleteWebhook(webhook.id)}>
                    Remove
                  </button>
                </div>
              </div>
              <div className="webhook-details">
                {webhook.event_types.map((eventType) => (
                  <span key={eventType} className="badge">
                    {eventType}
                  </span>
                ))}
              </div>
              {testMessage[webhook.id] && <p className="test-result">{testMessage[webhook.id]}</p>}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

interface WebhookFormProps {
  projectId: string;
  onSave: () => void;
  onCancel: () => void;
}

function WebhookForm({ projectId, onSave, onCancel }: WebhookFormProps) {
  const [service, setService] = useState<WebhookService>('slack');
  const [webhookUrl, setWebhookUrl] = useState('');
  const [eventTypes, setEventTypes] = useState<string[]>(['scan.completed']);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  function toggleEventType(eventType: string) {
    setEventTypes((current) =>
      current.includes(eventType) ? current.filter((e) => e !== eventType) : [...current, eventType]
    );
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (eventTypes.length === 0) {
      setError('Select at least one event type');
      return;
    }
    setLoading(true);
    setError('');
    try {
      await api.createWebhook(projectId, service, webhookUrl, eventTypes);
      onSave();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Error saving webhook');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="webhook-form-modal">
      <div className="modal-content">
        <h2>Add webhook</h2>
        {error && <div className="error-message">{error}</div>}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="webhook-service">Service *</label>
            <select id="webhook-service" value={service} onChange={(e) => setService(e.target.value as WebhookService)}>
              {SERVICES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </div>

          <div className="form-group">
            <label htmlFor="webhook-url">Webhook URL *</label>
            <input
              id="webhook-url"
              type="url"
              value={webhookUrl}
              onChange={(e) => setWebhookUrl(e.target.value)}
              placeholder="https://hooks.slack.com/services/…"
              required
            />
          </div>

          <div className="form-group">
            <label>Events *</label>
            {WEBHOOK_EVENT_TYPES.map((eventType) => (
              <label key={eventType} className="checkbox">
                <input
                  type="checkbox"
                  checked={eventTypes.includes(eventType)}
                  onChange={() => toggleEventType(eventType)}
                />
                {eventType}
              </label>
            ))}
          </div>

          <div className="form-actions">
            <button type="button" className="btn-secondary" onClick={onCancel}>
              Cancel
            </button>
            <button type="submit" className="btn-primary" disabled={loading}>
              {loading ? 'Saving...' : 'Save webhook'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
