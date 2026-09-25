import type { ReactNode, Ref } from "react";
import { useScrollReveal } from "../useScrollReveal";

/**
 * Wraps a marketing section so it fades/slides in the first time it scrolls
 * into view. Purely presentational — never gates content behind JS the way
 * a loading skeleton would; everything inside renders immediately in the
 * DOM (and to anything without JS/CSS), just visually held at opacity 0
 * until `.is-revealed` lands. See useScrollReveal for the
 * reduced-motion/no-IntersectionObserver fallback (shows instantly).
 */
export default function Reveal({ as: Tag = "div", className = "", id, children }: {
  as?: "div" | "section";
  className?: string;
  id?: string;
  children: ReactNode;
}) {
  const { ref, revealed } = useScrollReveal<HTMLElement>();
  // Tag is a runtime-chosen "div" | "section": both are plain HTMLElement
  // subtypes and useScrollReveal only touches generic HTMLElement members,
  // so this is a safe narrowing — TS just can't verify a polymorphic
  // intrinsic tag's ref type against a union of two concrete element types.
  return (
    <Tag ref={ref as Ref<HTMLDivElement>} id={id} className={`reveal ${revealed ? "is-revealed" : ""} ${className}`}>
      {children}
    </Tag>
  );
}
