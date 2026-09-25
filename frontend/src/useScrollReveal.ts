import { useEffect, useRef, useState } from "react";

// A section starts revealed (not hidden-then-animated-in) whenever the
// browser can't tell us it's actually out of view yet, or asks for reduced
// motion: no IntersectionObserver (old browsers, or jsdom in tests, which
// doesn't implement it) and prefers-reduced-motion both fall back to "just
// show it" rather than leaving marketing copy invisible.
function shouldRevealImmediately(): boolean {
  if (typeof window === "undefined" || typeof IntersectionObserver === "undefined") return true;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/**
 * Reveals an element (attach the returned ref to it) once it scrolls into
 * view, for a one-time fade/slide-in — never re-hides on scrolling back up.
 * Purely a CSS class toggle; the actual motion lives in styles.css so this
 * stays reusable for any marketing section without prescribing the effect.
 */
export function useScrollReveal<T extends HTMLElement>() {
  const ref = useRef<T | null>(null);
  const [revealed, setRevealed] = useState(shouldRevealImmediately);

  useEffect(() => {
    if (revealed) return; // already showing (or motion is disabled) — nothing to observe
    const el = ref.current;
    if (!el) return;

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setRevealed(true);
          observer.disconnect();
        }
      },
      { threshold: 0.15 }
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, [revealed]);

  return { ref, revealed };
}
