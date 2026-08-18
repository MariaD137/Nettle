import type { ScanJob } from "../api";

/**
 * Real-time step-by-step progress for a scan job — every step name comes
 * straight from what's actually running server-side (sourceScanSteps in
 * the scanner), not a client-side guess or a simulated countdown.
 */
export default function ScanProgress({ job }: { job: ScanJob | null }) {
  if (!job) {
    return <p className="muted scan-progress-waiting">Starting scan…</p>;
  }

  if (job.status === "queued") {
    return (
      <p className="muted scan-progress-waiting">
        {job.queuePosition && job.queuePosition > 0
          ? `Queued — ${job.queuePosition} scan${job.queuePosition === 1 ? "" : "s"} ahead of you.`
          : "Queued — starting shortly."}
      </p>
    );
  }

  return (
    <ul className="scan-progress-list">
      {job.steps.map((step) => (
        <li key={step.id} className={`scan-progress-step scan-progress-step-${step.status}`}>
          <span className="scan-progress-icon" aria-hidden="true">
            {step.status === "done" && "✓"}
            {step.status === "running" && <span className="scan-progress-spinner" />}
          </span>
          <span>{step.label}</span>
        </li>
      ))}
    </ul>
  );
}
