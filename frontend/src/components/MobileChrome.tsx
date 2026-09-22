import type { ReactNode } from "react";

/**
 * Native-style chrome for phones: a sticky app bar pinned to the top and a
 * fixed tab bar sitting in the thumb zone at the bottom. Both respect the
 * device safe areas so they clear the notch and the home indicator rather
 * than sliding under them.
 *
 * These render only on mobile — the desktop layout keeps its own topbar and
 * underlined tab row, which suit a pointer and a wide viewport.
 */

export function AppBar({
  title,
  subtitle,
  onBack,
  action,
}: {
  title: string;
  subtitle?: string;
  onBack?: () => void;
  action?: ReactNode;
}) {
  return (
    <header className="m-appbar">
      <div className="m-appbar-inner">
        {onBack ? (
          <button className="m-back" onClick={onBack} aria-label="Back">
            <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M15 18l-6-6 6-6" />
            </svg>
          </button>
        ) : (
          <span className="m-appbar-spacer" />
        )}
        <div className="m-appbar-titles">
          <span className="m-appbar-title">{title}</span>
          {subtitle && <span className="m-appbar-subtitle">{subtitle}</span>}
        </div>
        <div className="m-appbar-action">{action}</div>
      </div>
    </header>
  );
}

export interface TabItem {
  key: string;
  label: string;
  icon: ReactNode;
  badge?: number;
}

export function BottomNav({
  items,
  active,
  onSelect,
}: {
  items: TabItem[];
  active: string;
  onSelect: (key: string) => void;
}) {
  return (
    <nav className="m-bottomnav" aria-label="Sections">
      {items.map((it) => (
        <button
          key={it.key}
          className={`m-navitem ${active === it.key ? "active" : ""}`}
          onClick={() => onSelect(it.key)}
          aria-current={active === it.key ? "page" : undefined}
        >
          <span className="m-navicon">
            {it.icon}
            {it.badge ? <span className="m-navbadge">{it.badge > 9 ? "9+" : it.badge}</span> : null}
          </span>
          <span className="m-navlabel">{it.label}</span>
        </button>
      ))}
    </nav>
  );
}

// Stroke icons at a common 24px grid so they optically match each other.
const s = { fill: "none", stroke: "currentColor", strokeWidth: 1.9, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };

export const Icons = {
  overview: (
    <svg viewBox="0 0 24 24" width="23" height="23" {...s}>
      <rect x="3" y="3" width="7" height="7" rx="1.5" /><rect x="14" y="3" width="7" height="7" rx="1.5" />
      <rect x="3" y="14" width="7" height="7" rx="1.5" /><rect x="14" y="14" width="7" height="7" rx="1.5" />
    </svg>
  ),
  scan: (
    <svg viewBox="0 0 24 24" width="23" height="23" {...s}>
      <path d="M3 7V5a2 2 0 012-2h2M17 3h2a2 2 0 012 2v2M21 17v2a2 2 0 01-2 2h-2M7 21H5a2 2 0 01-2-2v-2" />
      <path d="M3 12h18" />
    </svg>
  ),
  findings: (
    <svg viewBox="0 0 24 24" width="23" height="23" {...s}>
      <path d="M10.3 3.9L1.9 18a2 2 0 001.7 3h16.8a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z" />
      <path d="M12 9v4M12 17h.01" />
    </svg>
  ),
  fixcenter: (
    <svg viewBox="0 0 24 24" width="23" height="23" {...s}>
      <path d="M14.7 6.3a4 4 0 01-5.4 5.4L4 17l3 3 5.3-5.3a4 4 0 015.4-5.4l-2.5 2.5-2-2z" />
    </svg>
  ),
  alerts: (
    <svg viewBox="0 0 24 24" width="23" height="23" {...s}>
      <path d="M18 8a6 6 0 00-12 0c0 7-3 9-3 9h18s-3-2-3-9" />
      <path d="M13.7 21a2 2 0 01-3.4 0" />
    </svg>
  ),
  history: (
    <svg viewBox="0 0 24 24" width="23" height="23" {...s}>
      <circle cx="12" cy="12" r="9" /><path d="M12 7v5l3.5 2" />
    </svg>
  ),
  settings: (
    <svg viewBox="0 0 24 24" width="23" height="23" {...s}>
      <path d="M4 6h16M4 12h16M4 18h16" /><circle cx="9" cy="6" r="2" fill="var(--surface)" />
      <circle cx="15" cy="12" r="2" fill="var(--surface)" /><circle cx="8" cy="18" r="2" fill="var(--surface)" />
    </svg>
  ),
  projects: (
    <svg viewBox="0 0 24 24" width="23" height="23" {...s}>
      <path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2z" />
    </svg>
  ),
  account: (
    <svg viewBox="0 0 24 24" width="23" height="23" {...s}>
      <circle cx="12" cy="8" r="3.6" /><path d="M4.5 20a7.5 7.5 0 0115 0" />
    </svg>
  ),
  chevron: (
    <svg viewBox="0 0 24 24" width="19" height="19" {...s} strokeWidth={2}>
      <path d="M9 6l6 6-6 6" />
    </svg>
  ),
};
