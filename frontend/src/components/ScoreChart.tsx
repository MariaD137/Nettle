import { useState } from "react";

export interface ScorePoint {
  id: string;
  scannedAt: string;
  score: number;
}

const WIDTH = 560;
const HEIGHT = 140;
const PAD_X = 12;
const PAD_TOP = 16;
const PAD_BOTTOM = 24;

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

// A single-series score-over-time line chart. Deliberately hand-rolled
// (no charting library) — one thin line, one accent color, index-spaced
// x-axis (scans aren't evenly spaced in time and forcing a true time
// scale would stretch/compress the shape misleadingly for a sparse
// history). `points` must be chronological, oldest first.
export default function ScoreChart({ points }: { points: ScorePoint[] }) {
  const [hovered, setHovered] = useState<number | null>(null);

  if (points.length === 0) return null;

  const innerW = WIDTH - PAD_X * 2;
  const innerH = HEIGHT - PAD_TOP - PAD_BOTTOM;
  const x = (i: number) => (points.length === 1 ? WIDTH / 2 : PAD_X + (i / (points.length - 1)) * innerW);
  const y = (score: number) => PAD_TOP + innerH * (1 - score / 100);

  const linePath = points.map((p, i) => `${i === 0 ? "M" : "L"} ${x(i).toFixed(1)} ${y(p.score).toFixed(1)}`).join(" ");
  const areaPath = points.length > 1
    ? `${linePath} L ${x(points.length - 1).toFixed(1)} ${(HEIGHT - PAD_BOTTOM).toFixed(1)} L ${x(0).toFixed(1)} ${(HEIGHT - PAD_BOTTOM).toFixed(1)} Z`
    : "";

  const first = points[0];
  const last = points[points.length - 1];
  const trendLabel =
    points.length > 1
      ? `Score trend: ${first.score} on ${formatDate(first.scannedAt)} to ${last.score} on ${formatDate(last.scannedAt)}, across ${points.length} scans.`
      : `Score: ${first.score}.`;

  function handleMove(e: React.MouseEvent<SVGSVGElement>) {
    const rect = e.currentTarget.getBoundingClientRect();
    const relX = ((e.clientX - rect.left) / rect.width) * WIDTH;
    let nearest = 0;
    let nearestDist = Infinity;
    points.forEach((_, i) => {
      const d = Math.abs(x(i) - relX);
      if (d < nearestDist) {
        nearestDist = d;
        nearest = i;
      }
    });
    setHovered(nearest);
  }

  const hoveredPoint = hovered !== null ? points[hovered] : null;

  return (
    <div className="score-chart" style={{ position: "relative" }}>
      <svg
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        role="img"
        aria-label={trendLabel}
        className="score-chart-svg"
        onMouseMove={handleMove}
        onMouseLeave={() => setHovered(null)}
      >
        {[0, 25, 50, 75, 100].map((tick) => (
          <line key={tick} x1={PAD_X} x2={WIDTH - PAD_X} y1={y(tick)} y2={y(tick)} className="score-chart-grid" />
        ))}
        {areaPath && <path d={areaPath} className="score-chart-area" />}
        {points.length > 1 && <path d={linePath} className="score-chart-line" />}
        {points.map((p, i) => (
          <circle
            key={p.id}
            cx={x(i)}
            cy={y(p.score)}
            r={hovered === i ? 5 : 3}
            className="score-chart-dot"
          />
        ))}
        {hovered !== null && (
          <line x1={x(hovered)} x2={x(hovered)} y1={PAD_TOP} y2={HEIGHT - PAD_BOTTOM} className="score-chart-crosshair" />
        )}
        <text x={x(0)} y={HEIGHT - 6} className="score-chart-axis-label" textAnchor="start">
          {formatDate(first.scannedAt)}
        </text>
        {points.length > 1 && (
          <text x={x(points.length - 1)} y={HEIGHT - 6} className="score-chart-axis-label" textAnchor="end">
            {formatDate(last.scannedAt)}
          </text>
        )}
      </svg>
      {hoveredPoint && (
        <div
          className="score-chart-tooltip"
          style={{ left: `${(x(hovered!) / WIDTH) * 100}%` }}
        >
          <strong>{hoveredPoint.score}</strong>
          <span>{new Date(hoveredPoint.scannedAt).toLocaleDateString()}</span>
        </div>
      )}
    </div>
  );
}
