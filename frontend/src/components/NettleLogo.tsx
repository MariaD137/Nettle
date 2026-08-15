/**
 * The Nettle mark: a bold geometric N whose left edge breaks apart into
 * squares that scatter outward and fade — the "digital disintegration"
 * construction, rendered in blue.
 *
 * Drawn with `currentColor` so the mark follows whatever text color its
 * container sets. That's what keeps it legible in both themes: the palette
 * defines a lighter blue for dark mode and the SVG picks it up for free.
 */

// Squares fall into five columns marching away from the stem. Each column
// steps down in size and opacity, and the rows are offset between columns so
// the field reads as debris rather than as a tidy grid. The nearest squares
// are close to the stem's own width, which is what sells them as pieces that
// broke off it.
const SHARDS: { x: number; y: number; size: number; opacity: number }[] = [
  // Column 1 — barely detached, near full weight.
  { x: 44, y: 6, size: 11, opacity: 0.95 },
  { x: 44, y: 30, size: 11, opacity: 0.9 },
  { x: 44, y: 56, size: 11, opacity: 0.95 },
  { x: 45, y: 78, size: 8, opacity: 0.75 },

  // Column 2 — spreading past the cap and baseline.
  { x: 30, y: 0, size: 9, opacity: 0.85 },
  { x: 30, y: 20, size: 9, opacity: 0.8 },
  { x: 31, y: 44, size: 8, opacity: 0.82 },
  { x: 30, y: 68, size: 9, opacity: 0.7 },
  { x: 32, y: 88, size: 6, opacity: 0.5 },

  // Column 3 — clearly breaking up.
  { x: 18, y: 10, size: 8, opacity: 0.62 },
  { x: 18, y: 34, size: 7, opacity: 0.6 },
  { x: 19, y: 58, size: 7, opacity: 0.58 },
  { x: 18, y: 80, size: 5, opacity: 0.45 },

  // Column 4 — scattering.
  { x: 8, y: 2, size: 6, opacity: 0.45 },
  { x: 8, y: 24, size: 6, opacity: 0.42 },
  { x: 9, y: 48, size: 5, opacity: 0.4 },
  { x: 8, y: 70, size: 5, opacity: 0.35 },

  // Column 5 — the last motes.
  { x: 0, y: 14, size: 5, opacity: 0.3 },
  { x: 1, y: 38, size: 4, opacity: 0.26 },
  { x: 1, y: 62, size: 4, opacity: 0.22 },
  { x: 2, y: 86, size: 3, opacity: 0.18 },
];

// Left stem x 58-76, right stem x 100-118, diagonal 22 units thick.
const N_PATH = "M58 15 H76 L100 63 V15 H118 V85 H100 L76 37 V85 H58 Z";

// Below this height the smallest shards land on sub-pixel boundaries and
// smear into a grey smudge, which reads as a rendering fault rather than as
// a dissolve. At favicon/topbar sizes the mark drops to just its chunky
// fragments, the way a real logo has a simplified small-size lockup.
const DETAIL_THRESHOLD = 32;
const MIN_SHARD_AT_SMALL_SIZE = 8;

export default function NettleLogo({
  size = 40,
  title = "Nettle",
}: {
  size?: number;
  title?: string;
}) {
  const shards =
    size >= DETAIL_THRESHOLD
      ? SHARDS
      : SHARDS.filter((s) => s.size >= MIN_SHARD_AT_SMALL_SIZE);

  return (
    <svg
      className="nettle-logo"
      width={(size * 130) / 100}
      height={size}
      viewBox="0 0 130 100"
      role="img"
      aria-label={title}
      fill="currentColor"
    >
      {shards.map((s, i) => (
        <rect key={i} x={s.x} y={s.y} width={s.size} height={s.size} opacity={s.opacity} />
      ))}
      <path d={N_PATH} />
    </svg>
  );
}
