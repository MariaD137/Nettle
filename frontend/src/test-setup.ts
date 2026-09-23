import "@testing-library/jest-dom/vitest";

// jsdom doesn't implement matchMedia at all — anything using useIsMobile
// (most pages, via MobileChrome) throws without this. A minimal stub is
// enough for tests: nothing here exercises actual media-query change events,
// just the desktop-vs-mobile branch each page renders on mount.
if (typeof window !== "undefined" && !window.matchMedia) {
  window.matchMedia = (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  }) as unknown as MediaQueryList;
}
