import type { Control } from "./types";

/**
 * The control library: a single in-memory registry of every Control
 * definition, keyed by controlKey. Library modules under ./library register
 * their controls at import time (see ./index.ts); nothing else should
 * construct a Control ad hoc inline in a scanner module.
 */
const registry = new Map<string, Control>();

export function registerControl(control: Control): void {
  if (registry.has(control.controlKey)) {
    throw new Error(`Control ${control.controlKey} is already registered — controlKey must be unique`);
  }
  registry.set(control.controlKey, control);
}

export function getControl(controlKey: string): Control | undefined {
  return registry.get(controlKey);
}

export function listControls(): Control[] {
  return Array.from(registry.values());
}

export function listControlsByCategory(category: string): Control[] {
  return listControls().filter((c) => c.category === category);
}

/** Test-only: clears the registry so test files don't leak controls into each other. */
export function __resetRegistryForTests(): void {
  registry.clear();
}
