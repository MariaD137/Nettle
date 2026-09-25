# Nettle explainer video — script & shot list

Source of truth for producing `frontend/public/media/nettle-explainer.mp4`,
the one asset the landing page's video section (`VideoSection.tsx`) still
needs — everything else (poster, captions, player, accessibility) is built
and live. Target runtime: 30–35 seconds (30–45s budget). Captions matching
this script's timing already exist at `frontend/public/media/nettle-explainer.vtt`;
if the final cut's timing differs, update that file to match.

No fake stats, customer logos, testimonials, or compliance/security
guarantees anywhere in this video — none of those exist elsewhere in the
Nettle product and none should be introduced here. Screens shown should be
the real Nettle UI (a real scan's findings, the real Fix Center, a real
status change) — recorded footage or a screen capture, not invented mockups.

| Time | Line | Visual |
|---|---|---|
| 0:00–0:03 | "AI can build your application fast." | An AI coding tool generating an app (editor/terminal, code scrolling). |
| 0:03–0:06.5 | "But fast doesn't always mean ready." | Cut to the same app; a subtle visual cue (dim/hold) that something's unverified. |
| 0:06.5–0:11 | "Nettle scans your application for security, legal, compliance, and readiness gaps." | The app enters Nettle — real upload/scan-start UI, scan running. |
| 0:11–0:16 | "Instead of just finding problems, Nettle explains what's missing and why it matters." | A real finding: evidence, severity/confidence, plain-language "why it matters." |
| 0:16–0:20.5 | "Nettle recommends practical ways to fix the gap." | The real Fix Center — quick fix / developer fix, tailored to the detected stack. |
| 0:20.5–0:24.5 | "Fix it. Rescan it. Verify it." | The same finding flipping from FAIL to a verified/passing state after a rescan. |
| 0:24.5–0:29 | "And keep monitoring as your application evolves." | Continuous-monitoring/alerts UI — the app running in production, Nettle still watching. |
| 0:29–0:34 | "Build fast. Know what you missed." / "Nettle" | Logo lockup, same mark as `frontend/src/components/NettleLogo.tsx`. |

**CTA (end card, optional overlay):** "Scan your app" → routes to `/login`
(the same destination the landing page's own hero CTA, "Scan your app
free," already uses — no new route needed).

## What this video must never claim

- Not "100% secure," "fully compliant," "guaranteed protection," "zero
  vulnerabilities," or "guaranteed compliance" — matches the product's own
  PASS / FAIL / NOT_VERIFIED honesty standard (see `MarketingPage.tsx`'s
  "Every finding is PASS, FAIL, or NOT_VERIFIED — never a guess" section).
- No fabricated customer count, testimonial, or security certification.

## Delivery

Drop the final file at `frontend/public/media/nettle-explainer.mp4`
(H.264/MP4, 16:9, ideally ≤ a few MB — it's fetched on demand via
`preload="none"`, not on page load, but still worth keeping light for
mobile). No code change is needed once it's in place — `VideoSection.tsx`
already points at that exact path.
