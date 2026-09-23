import { Link } from "react-router-dom";
import NettleLogo from "../components/NettleLogo";
import { PLANS } from "../plans";

/**
 * The public landing page (master spec §29/Phase F). Rendered at "/" for
 * anyone who isn't signed in — see App.tsx's HomeRoute, which keeps every
 * existing authenticated behavior (subscribe gate, dashboard) exactly as it
 * was and only adds this branch for the previously-unhandled "nobody's
 * signed in yet" case, which used to just bounce straight to /login with no
 * explanation of what Nettle even is.
 *
 * Every claim on this page is something Nettle's scanner or CLI actually
 * does today — the category list mirrors FindingCategory in
 * backend/src/scanner/types.ts, the pricing mirrors plans.ts (the same file
 * the real paywall renders from), and nothing here states a customer count,
 * a testimonial, or a stat Nettle has no data to back up.
 */

const CATEGORIES: { name: string; blurb: string }[] = [
  { name: "Authentication", blurb: "Password hashing, session/token expiry, MFA and reset-flow gaps." },
  { name: "Authorization & Multi-Tenant", blurb: "Resource ownership checks and cross-tenant data isolation." },
  { name: "API Security", blurb: "Auth, input validation and rate limiting on every endpoint." },
  { name: "Database", blurb: "Injection risk, access control and connection security." },
  { name: "Secrets & Cryptography", blurb: "Hardcoded credentials, weak hashing, exposed keys in bundles." },
  { name: "Frontend Security", blurb: "CSP, security headers and secrets leaking into shipped JS." },
  { name: "Payment Security", blurb: "Webhook signature checks and payment-secret handling." },
  { name: "Supply Chain", blurb: "Dependency vulnerabilities, typosquatting and non-registry packages." },
  { name: "CI/CD Security", blurb: "Pipeline permissions, secret scanning and deployment controls." },
  { name: "Cloud Security", blurb: "Dockerfile, security-group and public storage exposure." },
  { name: "AI-Assisted Code Risk", blurb: "Placeholder credentials and hardcoded-ID bypasses AI tools leave behind." },
  { name: "Legal & AI Disclosure", blurb: "Indicators that may call for privacy or AI-disclosure review." },
];

const STEPS: { title: string; detail: string }[] = [
  { title: "Scan", detail: "Upload a zip or point Nettle at a public repo — no install required to try it." },
  { title: "Understand", detail: "Every finding explains what was checked, what was found, and why it matters." },
  { title: "Fix", detail: "Recommendations are technology-aware: a fix for your actual stack, not a generic checklist." },
  { title: "Verify", detail: "Rescan to confirm the fix landed — the same check, the same evidence standard." },
  { title: "Monitor", detail: "PROTECT keeps watching after launch, with live alerts on suspicious traffic." },
];

export default function MarketingPage() {
  return (
    <div className="marketing-shell">
      <div className="topbar marketing-nav">
        <span className="brand"><NettleLogo size={26} title="" />nettle</span>
        <div className="topbar-right marketing-nav-links">
          <a href="#checks">What we check</a>
          <a href="#pricing">Pricing</a>
          <Link to="/login" className="button secondary">Log in</Link>
          <Link to="/login" className="button">Get started</Link>
        </div>
      </div>

      <section className="hero">
        <h1>Know what's actually wrong before you ship it.</h1>
        <p className="hero-sub">
          Nettle scans AI-built and AI-assisted apps for the security, legal, and
          compliance gaps their creators don't know to look for — then explains
          why each one matters and what to do about it, in your own stack's terms.
        </p>
        <div className="hero-cta">
          <Link to="/login" className="button">Scan your app free</Link>
          <a href="#how" className="button secondary">See how it works</a>
        </div>
      </section>

      <section className="marketing-honesty card">
        <h2>Every finding is PASS, FAIL, or NOT_VERIFIED — never a guess</h2>
        <p>
          If Nettle can't determine whether a control is actually satisfied — no
          production config supplied, no evidence either way — it says so
          explicitly instead of quietly assuming a pass. A finding that fails
          always comes with a quick fix, a developer-level fix, and a way to
          verify the fix worked, tailored to the frameworks Nettle detects in
          your codebase.
        </p>
      </section>

      <section id="how" className="marketing-section">
        <h2 className="marketing-section-title">How it works</h2>
        <div className="steps">
          {STEPS.map((s, i) => (
            <div className="step" key={s.title}>
              <span className="step-num">{i + 1}</span>
              <h3>{s.title}</h3>
              <p className="muted">{s.detail}</p>
            </div>
          ))}
        </div>
      </section>

      <section id="checks" className="marketing-section">
        <h2 className="marketing-section-title">What Nettle checks</h2>
        <p className="muted marketing-section-sub">
          A structured control library, not a static checklist — each category
          below only produces a result when Nettle actually has evidence to
          check it against.
        </p>
        <div className="feature-grid">
          {CATEGORIES.map((c) => (
            <div className="feature-card" key={c.name}>
              <h3>{c.name}</h3>
              <p className="muted">{c.blurb}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="marketing-section">
        <h2 className="marketing-section-title">Also ships as a CLI</h2>
        <p className="muted marketing-section-sub" style={{ marginBottom: 0 }}>
          Run <code>nettle scan</code> in CI and gate the build with{" "}
          <code>--fail-on critical</code> (or high, medium, low) — the same
          control library, in your pipeline.
        </p>
      </section>

      <section id="pricing" className="marketing-section">
        <h2 className="marketing-section-title">Pricing</h2>
        <div className="plan-grid">
          {PLANS.map((plan) => (
            <div key={plan.id} className={`plan-card ${plan.highlight ? "plan-card-highlight" : ""}`}>
              {plan.badge && <span className="plan-flag">{plan.badge}</span>}
              <h2>{plan.name}</h2>
              <p className="plan-tagline">{plan.tagline}</p>
              <div className="plan-price">
                <span className="plan-price-amount">{plan.price}</span>
                <span className="muted">{plan.cadence}</span>
              </div>
              <ul className="plan-features">
                {plan.features.map((f) => (
                  <li key={f}>
                    <span className="passed-icon" aria-hidden="true">&#10003;</span>
                    <span>{f}</span>
                  </li>
                ))}
                {plan.excluded?.map((f) => (
                  <li key={f} className="muted">
                    <span aria-hidden="true">&#10005;</span>
                    <span>{f}</span>
                  </li>
                ))}
              </ul>
              <Link
                to="/login"
                className={plan.highlight ? "button" : "button secondary"}
                style={{ width: "100%", textAlign: "center" }}
              >
                {plan.cta}
              </Link>
            </div>
          ))}
        </div>
      </section>

      <footer className="marketing-footer">
        <span className="brand"><NettleLogo size={20} title="" />nettle</span>
        <span className="muted">&copy; {new Date().getFullYear()} Nettle.</span>
      </footer>
    </div>
  );
}
