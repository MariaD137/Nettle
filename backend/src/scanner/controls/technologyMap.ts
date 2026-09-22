/**
 * Bridges frameworkDetection.ts's naming ("next.js", with a dot) to the
 * technology keys the control library's TechnologyFix entries actually use
 * ("nextjs", no dot) — the two vocabularies were written independently and
 * don't match verbatim. Anything frameworkDetection.ts can report that no
 * control has a fix for (react, vue, svelte, astro, remix, angular,
 * tailwind, typescript — all frontend/tooling signals, not the backend
 * routing frameworks AUTH-001/API-001 have fixes for) maps to undefined, so
 * hydration correctly falls back to each control's "generic" fix instead of
 * silently matching nothing.
 */
const FRAMEWORK_TO_TECHNOLOGY: Record<string, string> = {
  express: "express",
  fastapi: "fastapi",
  django: "django",
  flask: "flask",
  "next.js": "nextjs",
  nuxt: "nuxt",
};

export function mapFrameworkToTechnology(primaryFramework: string | null): string | undefined {
  if (!primaryFramework) return undefined;
  return FRAMEWORK_TO_TECHNOLOGY[primaryFramework];
}
