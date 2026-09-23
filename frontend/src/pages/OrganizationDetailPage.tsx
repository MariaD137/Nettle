import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  api,
  ApiError,
  type Organization,
  type OrganizationInvitation,
  type OrganizationMember,
  type OrganizationRole,
} from "../api";
import { useAuth } from "../AuthContext";
import NettleLogo from "../components/NettleLogo";
import { PLAN_LABELS } from "../plans";

interface Loaded {
  organization: Organization;
  role: OrganizationRole;
  members: OrganizationMember[];
}

export default function OrganizationDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { user } = useAuth();
  const [loaded, setLoaded] = useState<Loaded | null>(null);
  const [invitations, setInvitations] = useState<OrganizationInvitation[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notFound, setNotFound] = useState(false);

  function refresh() {
    if (!id) return;
    api
      .getOrganization(id)
      .then(setLoaded)
      .catch((err) => {
        if (err instanceof ApiError && err.status === 404) setNotFound(true);
        else setError(err instanceof ApiError ? err.message : "Couldn't load organization");
      });
  }

  function refreshInvitations() {
    if (!id || loaded?.role !== "owner") return;
    api
      .listInvitations(id)
      .then(({ invitations }) => setInvitations(invitations))
      .catch(() => {});
  }

  useEffect(() => { refresh(); }, [id]);
  useEffect(() => { refreshInvitations(); }, [id, loaded?.role]);

  if (notFound) {
    return (
      <div className="shell">
        <h1>Organization not found</h1>
        <Link to="/organizations">Back to organizations</Link>
      </div>
    );
  }

  const isOwner = loaded?.role === "owner";

  return (
    <div className="shell">
      <div className="topbar">
        <Link to="/" className="brand"><NettleLogo size={22} title="" />nettle</Link>
        <div className="topbar-right">
          <Link to="/organizations" className="settings-link">Organizations</Link>
          <Link to="/settings" className="settings-link">Settings</Link>
          <span>{user?.email}</span>
        </div>
      </div>

      {error && <div className="error-banner">{error}</div>}

      {loaded === null && !error && <p className="muted">Loading…</p>}

      {loaded && (
        <>
          <h1>{loaded.organization.name}</h1>

          {isOwner && <RenameCard organization={loaded.organization} onRenamed={refresh} />}

          <MembersCard
            members={loaded.members}
            ownerId={loaded.organization.ownerId}
            isOwner={isOwner}
            organizationId={loaded.organization.id}
            onChanged={refresh}
          />

          {isOwner && <BillingCard organization={loaded.organization} />}

          {isOwner && (
            <InvitationsCard
              organizationId={loaded.organization.id}
              invitations={invitations}
              onChanged={refreshInvitations}
            />
          )}
        </>
      )}
    </div>
  );
}

function RenameCard({ organization, onRenamed }: { organization: Organization; onRenamed: () => void }) {
  const [name, setName] = useState(organization.name);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await api.renameOrganization(organization.id, name);
      onRenamed();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't rename organization");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="card">
      <h2>Organization name</h2>
      {error && <div className="error-banner">{error}</div>}
      <form onSubmit={handleSubmit}>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-end" }}>
          <div className="field" style={{ flex: 1, marginBottom: 0 }}>
            <label htmlFor="rename">Name</label>
            <input id="rename" required value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <button type="submit" disabled={submitting || name.trim() === organization.name}>
            {submitting ? "Saving…" : "Save"}
          </button>
        </div>
      </form>
    </div>
  );
}

function MembersCard({
  members,
  ownerId,
  isOwner,
  organizationId,
  onChanged,
}: {
  members: OrganizationMember[];
  ownerId: string;
  isOwner: boolean;
  organizationId: string;
  onChanged: () => void;
}) {
  const [removing, setRemoving] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleRemove(userId: string) {
    setError(null);
    setRemoving(userId);
    try {
      await api.removeOrganizationMember(organizationId, userId);
      onChanged();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't remove member");
    } finally {
      setRemoving(null);
    }
  }

  return (
    <div className="card">
      <h2>Members</h2>
      {error && <div className="error-banner">{error}</div>}
      {members.map((m) => (
        <div key={m.id} className="settings-row" style={{ alignItems: "center" }}>
          <div>
            <span>{m.email}</span>{" "}
            <span className="plan-badge" style={{ marginLeft: 8 }}>{m.role}</span>
          </div>
          {isOwner && m.userId !== ownerId && (
            <button
              className="small destructive"
              disabled={removing === m.userId}
              onClick={() => handleRemove(m.userId)}
            >
              {removing === m.userId ? "Removing…" : "Remove"}
            </button>
          )}
        </div>
      ))}
    </div>
  );
}

// Mirrors backend/src/billing/orgSubscription.ts's hasActiveOrgSubscription
// — UI framing only, never an access decision (every route this gates is
// independently enforced server-side, same relationship as subscription.ts's
// personal-account equivalent).
function orgHasActiveSubscription(organization: Organization): boolean {
  return (
    (organization.plan === "build" || organization.plan === "protect") &&
    (organization.subscriptionStatus === "active" || organization.subscriptionStatus === "trialing")
  );
}

function BillingCard({ organization }: { organization: Organization }) {
  const [starting, setStarting] = useState<"build" | "protect" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const active = orgHasActiveSubscription(organization);

  async function subscribe(plan: "build" | "protect") {
    setError(null);
    setStarting(plan);
    try {
      const { url } = await api.createOrgCheckoutSession(organization.id, plan);
      window.location.href = url;
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't start checkout");
      setStarting(null);
    }
  }

  return (
    <div className="card">
      <h2>Organization billing</h2>
      <p className="muted" style={{ marginTop: -4 }}>
        Optional — subscribing the organization itself unlocks its plan for every member's access to its
        projects, independent of each member's own personal plan.
      </p>
      {error && <div className="error-banner">{error}</div>}
      <div className="settings-row">
        <span className="settings-label">Current plan</span>
        <span>
          <span className="plan-badge">{PLAN_LABELS[organization.plan] ?? organization.plan}</span>
          {!active && <span className="muted" style={{ marginLeft: 8 }}>not subscribed</span>}
        </span>
      </div>
      {!active && (
        <div style={{ display: "flex", gap: 10, marginTop: 12 }}>
          <button onClick={() => subscribe("build")} disabled={starting !== null}>
            {starting === "build" ? "Starting…" : "Subscribe to Build"}
          </button>
          <button className="secondary" onClick={() => subscribe("protect")} disabled={starting !== null}>
            {starting === "protect" ? "Starting…" : "Subscribe to Protect"}
          </button>
        </div>
      )}
    </div>
  );
}

function InvitationsCard({
  organizationId,
  invitations,
  onChanged,
}: {
  organizationId: string;
  invitations: OrganizationInvitation[] | null;
  onChanged: () => void;
}) {
  const [email, setEmail] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [sending, setSending] = useState(false);
  const [revoking, setRevoking] = useState<string | null>(null);

  async function handleInvite(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    setSending(true);
    try {
      const { delivered } = await api.createInvitation(organizationId, email);
      setSuccess(
        delivered
          ? `Invitation sent to ${email}.`
          : `Invitation created for ${email}, but email delivery isn't configured in this environment — share the accept link with them manually.`
      );
      setEmail("");
      onChanged();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't send invitation");
    } finally {
      setSending(false);
    }
  }

  async function handleRevoke(invitationId: string) {
    setError(null);
    setRevoking(invitationId);
    try {
      await api.revokeInvitation(organizationId, invitationId);
      onChanged();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't revoke invitation");
    } finally {
      setRevoking(null);
    }
  }

  return (
    <div className="card">
      <h2>Invite a member</h2>
      {error && <div className="error-banner">{error}</div>}
      {success && <div className="success-banner">{success}</div>}
      <form onSubmit={handleInvite}>
        <div style={{ display: "flex", gap: 10, alignItems: "flex-end" }}>
          <div className="field" style={{ flex: 1, marginBottom: 0 }}>
            <label htmlFor="invite-email">Email</label>
            <input
              id="invite-email"
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="teammate@example.com"
            />
          </div>
          <button type="submit" disabled={sending}>
            {sending ? "Sending…" : "Invite"}
          </button>
        </div>
      </form>

      {invitations && invitations.length > 0 && (
        <>
          <h2 style={{ marginTop: 20 }}>Pending invitations</h2>
          {invitations.map((inv) => (
            <div key={inv.id} className="settings-row" style={{ alignItems: "center" }}>
              <div>
                <span>{inv.email}</span>{" "}
                <span className="muted" style={{ marginLeft: 8 }}>
                  expires {new Date(inv.expiresAt).toLocaleDateString()}
                </span>
              </div>
              <button
                className="small destructive"
                disabled={revoking === inv.id}
                onClick={() => handleRevoke(inv.id)}
              >
                {revoking === inv.id ? "Revoking…" : "Revoke"}
              </button>
            </div>
          ))}
        </>
      )}
    </div>
  );
}
