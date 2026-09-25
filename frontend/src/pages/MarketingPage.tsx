import { Link } from "react-router-dom";
import NettleLogo from "../components/NettleLogo";
import Reveal from "../components/Reveal";
import VideoSection from "../components/VideoSection";
import { PLANS } from "../plans";

/**
 * The public landing page. Rendered at "/" for anyone who isn't signed in —
 * see App.tsx's HomeRoute, which keeps every existing authenticated
 * behavior (subscribe gate, dashboard) exactly as it was and only adds this
 * branch for the "nobody's signed in yet" case.
 *
 * Every claim on this page traces to something actually implemented in the
 * repository: the category list mirrors the real controls under
 * backend/src/scanner/controls/library/, the PASS/FAIL/NOT_VERIFIED model
 * mirrors scanner/threeStateModel.ts, the diff statuses mirror
 * scanner/scanComparison.ts's DiffStatus union, the Fix Center field names
 * (Quick fix / Developer fix / Architecture fix / Long-term hardening /
 * Verification) mirror ProjectPage.tsx's own Fix Center UI, the illustrative
 * finding is SECRET-001's real content from
 * scanner/controls/library/secrets.ts, and the pricing mirrors plans.ts (the
 * same file the real paywall renders from). Nothing here states a customer
 * count, a testimonial, or a stat Nettle has no data to back up.
 */

const CATEGORIES: { name: string; blurb: string }[] = [
  { name: "Authentication & Sessions", blurb: "Server-side auth enforcement, JWT expiry and signing algorithm, refresh-token rotation, session expiration, and logout invalidation." },
  { name: "API Security", blurb: "Rate limiting, request-schema validation, CSRF protection, CORS restrictions, request-size limits, and file-upload restrictions." },
  { name: "Database Security", blurb: "Parameterized queries and ORM usage, and no database connection string hardcoded in source." },
  { name: "Secrets & Cryptography", blurb: "Hardcoded credentials, API keys, and connection strings, plus weak or deprecated cryptographic primitives." },
  { name: "Application Security", blurb: "Unsafe eval() usage, command injection, path traversal, unsafe deserialization, and unencrypted transport." },
  { name: "Frontend & Browser Security", blurb: "Sensitive data left in localStorage/sessionStorage, and security response headers like CSP and HSTS." },
  { name: "Dependencies & Supply Chain", blurb: "Known-vulnerable dependencies, a committed lockfile, and package names that resemble a typosquat of a well-known library." },
  { name: "AI Application Security", blurb: "Prompt injection exposure, AI API cost/token limits, tool-execution allowlisting, and validation of AI model output before use." },
  { name: "AI-Assisted Code Review", blurb: "Placeholder credentials and excessive debug output the kind of thing AI coding tools leave behind." },
  { name: "Payment Security", blurb: "Webhook signature verification on payment events." },
  { name: "CI/CD Security", blurb: "Pipeline patterns that let a pull request's own code influence a privileged workflow run." },
  { name: "Cloud Security", blurb: "Container configuration, such as whether it runs as a non-root user." },
  { name: "Multi-Tenant Security", blurb: "Tenant or organization IDs trusted from client input instead of the authenticated session." },
  { name: "Legal & Policy Readiness", blurb: "Indicators like whether a privacy policy is present — a signal for review, not a legal determination." },
];

const WORKFLOW_STEPS: { title: string; detail: string }[] = [
  { title: "Scan", detail: "Nettle examines your application and whatever evidence is available to it. Upload a zip or point it at a public repo — no install required." },
  { title: "Check", detail: "Every file, route, and dependency is evaluated against Nettle's control library: the same structured checks every time, not one-off opinions." },
  { title: "Identify the gap", detail: "Nettle flags every control that fails, and separately flags any control it doesn't have enough evidence to confirm. The two are never treated as the same thing." },
  { title: "Explain", detail: "Each finding shows what was checked, what was found, why it matters, its severity and confidence, and the technology it applies to." },
  { title: "Recommend", detail: "The Fix Center gives a quick fix and a developer fix for every finding, plus an architecture fix and long-term hardening step where the control supports them." },
  { title: "Implement", detail: "You make the change, in your own codebase, on your own timeline. Nettle explains and recommends — it never edits your code for you." },
  { title: "Rescan", detail: "Run Nettle again on the updated code — the same control library, applied the same way, so the comparison is fair." },
  { title: "Verify", detail: "Nettle compares the two scans and marks each finding FIXED, STILL_OPEN, NEW, REGRESSED, CHANGED, or NOT_VERIFIED. Never a guessed pass." },
  { title: "Monitor", detail: "Once you ship, PROTECT keeps watching your live application and raises an alert on suspicious traffic, like repeated failed logins or path-traversal attempts." },
];

const PROBLEM_EXAMPLES: string[] = [
  "A route that looks protected but is missing its authorization check",
  "A secret or API key committed straight into source",
  "A dependency with a known vulnerability, sitting unnoticed in the lockfile",
  "An API with no rate limiting or request-size limit",
  "File uploads accepted with no type or size restriction",
  "A session or JWT that never expires, or a logout that doesn't invalidate it",
  "Security response headers left at their framework defaults",
  "A tenant or organization ID trusted from client input instead of the session",
  "AI-generated content with no visible disclosure that it's AI-generated",
  "A privacy policy that was never written",
];

const DIFF_LEGEND: { status: string; pillClass: string; detail: string }[] = [
  { status: "FIXED", pillClass: "diff-fixed", detail: "Open in the baseline scan, not detected in the current one, and nothing else makes that comparison unsafe." },
  { status: "STILL_OPEN", pillClass: "diff-stillopen", detail: "Present in both scans, unchanged." },
  { status: "NEW", pillClass: "diff-new", detail: "Not present in the baseline scan, and not a reappearance of something seen in an earlier scan either." },
  { status: "REGRESSED", pillClass: "diff-regressed", detail: "This exact issue was fixed in an earlier scan and has come back." },
  { status: "CHANGED", pillClass: "diff-changed", detail: "Present in both scans, but something meaningful changed — severity, confidence, location, or evidence." },
  { status: "NOT_VERIFIED", pillClass: "diff-notverified", detail: "Nettle can't safely call this FIXED, NEW, or REGRESSED — usually a scan didn't complete, a file couldn't be read, or the control's definition changed. Not evidence the app is clean." },
];

const WHO_FOR: string[] = [
  "Indie developers and solo builders shipping an AI-assisted app for the first time",
  "Small teams who moved fast with AI tooling and want a second, independent pass before launch",
  "Teams preparing for a security or compliance review who want evidence gathered ahead of time",
  "Anyone who wants their application checked again after every meaningful change, not just once",
];

const NOT_LIST: string[] = [
  "A guarantee that your application is secure",
  "A replacement for a professional security audit, code review, or penetration test",
  "A legal opinion",
  "A guarantee of regulatory compliance",
  "A replacement for secure development practices on your own team",
];

const LOOP = ["Scan", "Check", "Identify gap", "Explain", "Recommend", "Implement", "Rescan", "Verify", "Monitor"];
const LIFECYCLE = ["Build", "Scan", "Fix", "Rescan", "Verify", "Ship", "Monitor"];

const FAQ: { q: string; a: string }[] = [
  { q: "What is Nettle?", a: "A security, legal, compliance, and readiness advisor for applications — especially ones built with AI coding assistants or fast, AI-assisted development. Nettle scans your application against a structured control library and explains what it finds." },
  { q: "Who is Nettle for?", a: "Indie developers, small teams, and anyone shipping an AI-assisted application who wants a second, independent pass before launch — and after every change that follows." },
  { q: "What does Nettle scan?", a: "Your application's source code and the evidence available in it — authentication, API security, database security, secrets and cryptography, dependencies, frontend security, AI-specific risks, payment security, CI/CD, cloud configuration, multi-tenant isolation, and legal/policy indicators. See “What is Nettle?” above for the full list." },
  { q: "Does Nettle fix vulnerabilities automatically?", a: "No. Nettle recommends a fix — a quick fix, a developer fix, and where relevant an architecture fix — but you implement the change yourself. Nettle never modifies your code." },
  { q: "Does Nettle guarantee compliance?", a: "No. Nettle can identify legal and policy indicators and surface areas that may need review, but it doesn't issue a compliance certification and can't replace qualified legal review." },
  { q: "Can Nettle verify a fix?", a: "Yes — that's the core of the product. Rescan after you make a change, and Nettle compares the two scans and tells you whether each finding is FIXED, STILL_OPEN, NEW, REGRESSED, CHANGED, or NOT_VERIFIED." },
  { q: "Can I use Nettle for an AI-generated application?", a: "Yes — that's specifically what Nettle is built for. It checks the application the same way regardless of how it was built, including flagging AI-assisted-development risk indicators like placeholder credentials." },
  { q: "When should I run a Nettle scan?", a: "Before you ship, and again after any meaningful change. Nettle is designed to be run repeatedly, not just once." },
];

function LoopChain({ items }: { items: string[] }) {
  return (
    <div className="loop-chain" role="list" aria-label="Nettle's workflow">
      {items.map((item, i) => (
        <span className="loop-chip-wrap" key={item} role="listitem">
          <span className="loop-chip">{item}</span>
          {i < items.length - 1 && <span className="loop-arrow" aria-hidden="true">&rarr;</span>}
        </span>
      ))}
    </div>
  );
}

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
        <span className="hero-eyebrow">Scan &middot; Explain &middot; Fix &middot; Verify &middot; Monitor</span>
        <h1>Know what your AI-built application missed.</h1>
        <p className="hero-sub">
          Nettle scans AI-built and AI-assisted applications for security, legal,
          compliance, and readiness gaps, explains what it finds, recommends
          practical fixes, and helps you verify those fixes before and after you ship.
        </p>
        <div className="hero-cta">
          <Link to="/login" className="button">Scan your app free</Link>
          <a href="#how" className="button secondary">See how it works</a>
        </div>
      </section>

      <Reveal className="video-reveal">
        <VideoSection />
      </Reveal>

      <Reveal as="section" id="checks" className="marketing-section">
        <h2 className="marketing-section-title">What is Nettle?</h2>
        <p className="muted marketing-section-sub">
          Nettle is a security and readiness advisor for applications built with AI
          coding assistants, AI-generated scaffolding, or fast, AI-assisted
          development. It answers one question: what did the AI-generated code
          miss? Nettle checks your application against a structured control
          library, and for each control it says whether the application passes,
          fails, or whether there simply isn't enough evidence yet to say.
        </p>
        <div className="feature-grid">
          {CATEGORIES.map((c) => (
            <div className="feature-card" key={c.name}>
              <h3>{c.name}</h3>
              <p className="muted">{c.blurb}</p>
            </div>
          ))}
        </div>
      </Reveal>

      <Reveal as="section" className="marketing-section">
        <h2 className="marketing-section-title">AI helps you build. Nettle helps you inspect.</h2>
        <p className="muted marketing-section-sub">
          AI-assisted development can take an application from idea to running
          code fast. That speed is real, and it isn't the problem. The problem is
          that fast-generated code can leave gaps behind that are easy to miss —
          not because AI-generated code is inherently insecure, but because
          nobody looked closely at what shipped. A few examples of what those
          gaps actually look like:
        </p>
        <ul className="problem-list">
          {PROBLEM_EXAMPLES.map((p) => (
            <li key={p}>
              <span className="problem-marker" aria-hidden="true" />
              <span>{p}</span>
            </li>
          ))}
        </ul>
      </Reveal>

      <Reveal as="section" className="marketing-honesty">
        <h2>Every finding is PASS, FAIL, or NOT_VERIFIED. Never a guess.</h2>
        <p>
          When Nettle can't confirm a control is satisfied, it says so instead
          of assuming a pass. NOT_VERIFIED doesn't mean your application is
          secure — it means Nettle doesn't have enough evidence to confirm the
          control either way. Every failed finding ships with a quick fix, a
          developer fix, and a way to verify it worked.
        </p>
      </Reveal>

      <Reveal as="section" id="how" className="marketing-section">
        <h2 className="marketing-section-title">How Nettle works</h2>
        <p className="muted marketing-section-sub">The core loop, every time:</p>
        <LoopChain items={LOOP} />
        <div className="steps" style={{ marginTop: 32 }}>
          {WORKFLOW_STEPS.map((s, i) => (
            <div className="step" key={s.title}>
              <span className="step-num">{String(i + 1).padStart(2, "0")}</span>
              <h3>{s.title}</h3>
              <p className="muted">{s.detail}</p>
            </div>
          ))}
        </div>
      </Reveal>

      <Reveal as="section" className="marketing-section">
        <h2 className="marketing-section-title">Findings &amp; the Fix Center</h2>
        <p className="muted marketing-section-sub">
          Nettle doesn't stop at identifying a problem. Every finding that fails
          comes with a recommendation, and every recommendation has a path back
          to verification: <strong>Finding &rarr; Recommendation &rarr; Fix &rarr; Rescan &rarr; Verification</strong>.
          A finding shows what was checked, what was found, and why it matters;
          the Fix Center gives a quick fix, a developer fix, and where relevant
          an architecture fix and long-term hardening step, matched to your
          detected stack.
        </p>
      </Reveal>

      <Reveal as="section" className="marketing-section">
        <h2 className="marketing-section-title">Rescan &amp; verification</h2>
        <p className="muted marketing-section-sub">
          A one-time report says <em>&ldquo;here is a problem.&rdquo;</em> Nettle is built
          to also say <em>&ldquo;here is what changed after you fixed it,&rdquo;</em> by
          comparing your current scan against a prior one, finding by finding.
        </p>
        <div className="diff-legend">
          {DIFF_LEGEND.map((d) => (
            <div className="diff-legend-item" key={d.status}>
              <span className={`diff-pill ${d.pillClass}`}>{d.status}</span>
              <p className="muted">{d.detail}</p>
            </div>
          ))}
        </div>
      </Reveal>

      <Reveal as="section" className="marketing-section">
        <h2 className="marketing-section-title">Legal &amp; compliance</h2>
        <p className="muted marketing-section-sub">
          Nettle can identify legal and policy indicators — like whether a
          privacy policy is present — and can flag content that may need an
          AI-disclosure statement. It does not determine whether your
          application is legally compliant, and a passing control is not a
          compliance certification. Legal and regulatory determinations require
          qualified professional review; Nettle is built to help you prepare
          for that review with evidence attached to every finding, not to
          replace it.
        </p>
      </Reveal>

      <Reveal as="section" className="marketing-section">
        <h2 className="marketing-section-title">Built by AI. Reviewed by Nettle.</h2>
        <p className="muted marketing-section-sub">
          AI coding tools make it faster than ever to go from an idea to a
          running application, and they're genuinely good at writing code that
          works. They're not designed to tell you what they left out. Nettle
          exists to close that gap — not by warning you away from AI-assisted
          development, but by giving what got built a second, independent pass:
          what it satisfies, what it doesn't, and what there simply isn't
          enough evidence to say yet. Whether the code came from an AI
          pair-programmer, a fully AI-generated scaffold, or a weekend of vibe
          coding, Nettle checks it the same way.
        </p>
      </Reveal>

      <Reveal as="section" className="marketing-section">
        <h2 className="marketing-section-title">Who Nettle is for</h2>
        <ul className="problem-list">
          {WHO_FOR.map((w) => (
            <li key={w}>
              <span className="passed-icon" aria-hidden="true">&#10003;</span>
              <span>{w}</span>
            </li>
          ))}
        </ul>
      </Reveal>

      <Reveal as="section" className="marketing-section">
        <h2 className="marketing-section-title">When to use Nettle</h2>
        <LoopChain items={LIFECYCLE} />
        <p className="muted marketing-section-sub" style={{ marginTop: 20 }}>
          Run Nettle before you ship, and again every time the application
          changes materially after that. It doesn't stop being useful the day
          you launch.
        </p>
      </Reveal>

      <Reveal as="section" className="marketing-section">
        <h2 className="marketing-section-title">What Nettle is not</h2>
        <ul className="problem-list">
          {NOT_LIST.map((n) => (
            <li key={n} className="muted">
              <span aria-hidden="true">&#10005;</span>
              <span>{n}</span>
            </li>
          ))}
        </ul>
        <p className="muted marketing-section-sub" style={{ marginTop: 20 }}>
          Nettle is an advisor: it identifies, explains, and helps you
          remediate and verify gaps. The judgment calls stay yours.
        </p>
      </Reveal>

      <Reveal as="section" className="marketing-section">
        <p className="muted marketing-section-sub" style={{ marginBottom: 0 }}>
          Run <code>nettle scan</code> in CI and gate the build with{" "}
          <code>--fail-on critical</code> (or high, medium, low) — the same
          control library, in your pipeline.
        </p>
      </Reveal>

      <Reveal as="section" id="pricing" className="marketing-section">
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
      </Reveal>

      <Reveal as="section" className="marketing-section">
        <h2 className="marketing-section-title">Frequently asked questions</h2>
        <div className="faq-list">
          {FAQ.map((item) => (
            <details className="faq-item" key={item.q}>
              <summary>{item.q}</summary>
              <p className="muted">{item.a}</p>
            </details>
          ))}
        </div>
      </Reveal>

      <Reveal as="section" className="marketing-final-cta">
        <h2>Built with AI. Ready for review?</h2>
        <p>Find what was missed. Understand why it matters. Fix it. Rescan it. Verify it.</p>
        <Link to="/login" className="button">Scan your app free</Link>
      </Reveal>

      <footer className="marketing-footer">
        <span className="brand"><NettleLogo size={20} title="" />nettle</span>
        <span className="muted">&copy; {new Date().getFullYear()} Nettle.</span>
      </footer>
    </div>
  );
}
