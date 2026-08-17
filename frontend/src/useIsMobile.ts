import { useEffect, useState } from "react";

// Single source of truth for the phone breakpoint, matched to the same
// 700px the stylesheet uses. Kept as a media query rather than a width
// comparison so it re-evaluates on rotation without a resize listener.
export const MOBILE_QUERY = "(max-width: 700px)";

export function useIsMobile(): boolean {
  const [isMobile, setIsMobile] = useState(
    () => typeof window !== "undefined" && window.matchMedia(MOBILE_QUERY).matches
  );

  useEffect(() => {
    const mq = window.matchMedia(MOBILE_QUERY);
    const onChange = (e: MediaQueryListEvent) => setIsMobile(e.matches);
    mq.addEventListener("change", onChange);
    setIsMobile(mq.matches);
    return () => mq.removeEventListener("change", onChange);
  }, []);

  return isMobile;
}
