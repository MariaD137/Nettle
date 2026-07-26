import type { BadgeState } from "../api";

export default function BadgePill({ state }: { state: BadgeState }) {
  return (
    <span className={`pill pill-${state.status}`}>
      <span className="dot" />
      {state.label}
    </span>
  );
}
