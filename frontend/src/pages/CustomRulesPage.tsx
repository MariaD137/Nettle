import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { api, ApiError, type CustomRule } from '../api';
import './CustomRulesPage.css';

export function CustomRulesPage() {
  const { projectId } = useParams<{ projectId: string }>();
  const [rules, setRules] = useState<CustomRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showForm, setShowForm] = useState(false);
  const [selectedRule, setSelectedRule] = useState<CustomRule | null>(null);

  useEffect(() => {
    if (projectId) loadRules();
  }, [projectId]);

  async function loadRules() {
    if (!projectId) return;
    try {
      setLoading(true);
      const { rules } = await api.listCustomRules(projectId);
      setRules(rules);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Error loading rules');
    } finally {
      setLoading(false);
    }
  }

  async function deleteRule(ruleId: string) {
    if (!projectId) return;
    if (confirm('Are you sure you want to delete this rule?')) {
      try {
        await api.deleteCustomRule(projectId, ruleId);
        setRules(rules.filter(r => r.id !== ruleId));
      } catch (err) {
        setError(err instanceof ApiError ? err.message : 'Failed to delete rule');
      }
    }
  }

  async function toggleRule(rule: CustomRule) {
    if (!projectId) return;
    try {
      await api.updateCustomRule(projectId, rule.id, { enabled: !rule.enabled });
      loadRules();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to update rule');
    }
  }

  if (loading) return <div className="loading">Loading rules...</div>;

  return (
    <div className="custom-rules-page">
      <div className="page-header">
        <h1>Custom Detection Rules</h1>
        <button
          className="btn-primary"
          onClick={() => {
            setSelectedRule(null);
            setShowForm(true);
          }}
        >
          + Create Rule
        </button>
      </div>

      {error && <div className="error-message">{error}</div>}

      {showForm && (
        <RuleForm
          projectId={projectId!}
          rule={selectedRule}
          onSave={() => {
            setShowForm(false);
            loadRules();
          }}
          onCancel={() => setShowForm(false)}
        />
      )}

      <div className="rules-list">
        {rules.length === 0 ? (
          <div className="empty-state">
            <p>No custom rules yet. Create one to start detecting custom patterns.</p>
          </div>
        ) : (
          rules.map(rule => (
            <div key={rule.id} className="rule-card">
              <div className="rule-header">
                <div>
                  <h3>{rule.name}</h3>
                  {rule.description && <p className="description">{rule.description}</p>}
                </div>
                <div className="rule-actions">
                  <label className="toggle">
                    <input
                      type="checkbox"
                      checked={rule.enabled}
                      onChange={() => toggleRule(rule)}
                    />
                    <span>{rule.enabled ? 'Enabled' : 'Disabled'}</span>
                  </label>
                  <button
                    className="btn-secondary"
                    onClick={() => {
                      setSelectedRule(rule);
                      setShowForm(true);
                    }}
                  >
                    Edit
                  </button>
                  <button
                    className="btn-danger"
                    onClick={() => deleteRule(rule.id)}
                  >
                    Delete
                  </button>
                </div>
              </div>
              <div className="rule-details">
                <span className="badge">{rule.pattern_type}</span>
                <span className={`severity severity-${rule.severity}`}>{rule.severity}</span>
                <span className="weight">Weight: {rule.weight}</span>
                <span className="version">v{rule.version}</span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

interface RuleFormProps {
  projectId: string;
  rule?: CustomRule | null;
  onSave: () => void;
  onCancel: () => void;
}

function RuleForm({ projectId, rule, onSave, onCancel }: RuleFormProps) {
  const [formData, setFormData] = useState({
    name: rule?.name || '',
    description: rule?.description || '',
    pattern_type: rule?.pattern_type || 'exact',
    pattern_value: '',
    weight: rule?.weight || 50,
    severity: rule?.severity || 'medium',
    enabled: rule?.enabled ?? true,
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);

    try {
      if (rule) {
        await api.updateCustomRule(projectId, rule.id, formData);
      } else {
        await api.createCustomRule(projectId, formData);
      }
      onSave();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Error saving rule');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="rule-form-modal">
      <div className="modal-content">
        <h2>{rule ? 'Edit Rule' : 'Create Custom Rule'}</h2>
        {error && <div className="error-message">{error}</div>}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Rule Name *</label>
            <input
              type="text"
              value={formData.name}
              onChange={e => setFormData({ ...formData, name: e.target.value })}
              required
            />
          </div>

          <div className="form-group">
            <label>Description</label>
            <textarea
              value={formData.description}
              onChange={e => setFormData({ ...formData, description: e.target.value })}
              placeholder="What does this rule detect?"
            />
          </div>

          <div className="form-row">
            <div className="form-group">
              <label>Pattern Type *</label>
              <select
                value={formData.pattern_type}
                onChange={e => setFormData({ ...formData, pattern_type: e.target.value as CustomRule["pattern_type"] })}
              >
                <option value="exact">Exact Match</option>
                <option value="regex">Regular Expression</option>
                <option value="threshold">Threshold</option>
                <option value="combination">Combination</option>
              </select>
            </div>

            <div className="form-group">
              <label>Severity *</label>
              <select
                value={formData.severity}
                onChange={e => setFormData({ ...formData, severity: e.target.value as CustomRule["severity"] })}
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
          </div>

          <div className="form-row">
            <div className="form-group">
              <label>Weight (0-100) *</label>
              <input
                type="number"
                min="0"
                max="100"
                value={formData.weight}
                onChange={e => setFormData({ ...formData, weight: parseInt(e.target.value) })}
                required
              />
            </div>
          </div>

          <div className="form-group">
            <label>Pattern Value *</label>
            <textarea
              value={formData.pattern_value}
              onChange={e => setFormData({ ...formData, pattern_value: e.target.value })}
              placeholder={getPatternPlaceholder(formData.pattern_type)}
              required
            />
            <small>{getPatternHelp(formData.pattern_type)}</small>
          </div>

          <div className="form-group">
            <label className="checkbox">
              <input
                type="checkbox"
                checked={formData.enabled}
                onChange={e => setFormData({ ...formData, enabled: e.target.checked })}
              />
              Enabled
            </label>
          </div>

          <div className="form-actions">
            <button type="button" className="btn-secondary" onClick={onCancel}>
              Cancel
            </button>
            <button type="submit" className="btn-primary" disabled={loading}>
              {loading ? 'Saving...' : 'Save Rule'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function getPatternPlaceholder(type: string): string {
  switch (type) {
    case 'regex':
      return '/api/admin|/wp-admin|^/internal/';
    case 'threshold':
      return 'ip:>10';
    case 'combination':
      return 'method=POST&status_code=403';
    default:
      return '/api/admin';
  }
}

function getPatternHelp(type: string): string {
  switch (type) {
    case 'regex':
      return 'JavaScript regular expression pattern (tested against path)';
    case 'threshold':
      return 'Format: field:operatorN (e.g. ip:>=10) — fires when more than N events in the last 60s share the same value for that field as the one being evaluated';
    case 'combination':
      return 'Format: field1=value1&field2=value2 (AND) or field1=value1|field2=value2 (OR)';
    default:
      return 'Exact string match on request path';
  }
}
