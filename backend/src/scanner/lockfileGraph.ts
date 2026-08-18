import fs from "fs";

/**
 * npm lockfileVersion 2/3 "packages" map: a flat object keyed by the
 * package's node_modules install path ("" for the project root itself,
 * "node_modules/foo", "node_modules/foo/node_modules/bar" for something
 * nested under foo, and so on). Each entry lists the *names* (not paths) it
 * directly depends on — resolving a name to the specific installed
 * instance it actually points at requires walking node_modules boundaries
 * the same way Node's own require() resolution does, which is what
 * resolveDependency below does.
 */
interface LockfilePackageEntry {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

export interface LockfileGraph {
  packages: Record<string, LockfilePackageEntry>;
}

// A defensive ceiling — this runs synchronously inside a scan request, so a
// pathological lockfile should be skipped rather than allowed to hang it.
const MAX_PACKAGES = 20_000;
const MAX_PATHS = 5;
const MAX_DEPTH = 12;

export function parseLockfileGraph(lockfileContents: string): LockfileGraph | null {
  let json: any;
  try {
    json = JSON.parse(lockfileContents);
  } catch {
    return null;
  }

  // Only lockfileVersion 2/3 (npm 7+) use the flat `packages` map this
  // resolver relies on. Version 1's nested `dependencies` tree has a
  // different (and more ambiguous) shape — not supported here.
  if (!json || typeof json !== "object" || !json.packages || typeof json.packages !== "object") {
    return null;
  }
  if (Object.keys(json.packages).length > MAX_PACKAGES) {
    return null;
  }

  return { packages: json.packages };
}

export function loadLockfileGraph(lockfilePath: string): LockfileGraph | null {
  if (!fs.existsSync(lockfilePath)) return null;
  try {
    return parseLockfileGraph(fs.readFileSync(lockfilePath, "utf8"));
  } catch {
    return null;
  }
}

/** "node_modules/@scope/a/node_modules/b" -> ["@scope/a", "b"]. Root ("") -> []. */
function pathSegments(pkgPath: string): string[] {
  if (!pkgPath) return [];
  return pkgPath
    .split("node_modules/")
    .slice(1)
    .map((s) => s.replace(/\/$/, ""));
}

function packageNameAt(path: string, entry: LockfilePackageEntry | undefined): string {
  if (entry?.name) return entry.name;
  const segs = pathSegments(path);
  return segs[segs.length - 1] ?? path;
}

/**
 * The install-path candidates Node's own require() resolution would check,
 * in order, when the package installed at `fromPath` requires `depName` —
 * its own nested node_modules first, then each ancestor's, ending at the
 * project root's node_modules.
 */
function resolutionCandidates(fromPath: string, depName: string): string[] {
  const segs = pathSegments(fromPath);
  const candidates: string[] = [];
  for (let i = segs.length; i >= 0; i--) {
    const prefix = segs
      .slice(0, i)
      .map((s) => `node_modules/${s}`)
      .join("/");
    candidates.push(prefix ? `${prefix}/node_modules/${depName}` : `node_modules/${depName}`);
  }
  return candidates;
}

function resolveDependency(graph: LockfileGraph, fromPath: string, depName: string): string | null {
  for (const candidate of resolutionCandidates(fromPath, depName)) {
    if (graph.packages[candidate]) return candidate;
  }
  return null;
}

interface ParentEdge {
  parentPath: string;
}

/**
 * Reverse-adjacency: for every package that declares a dependency, resolve
 * which specific installed instance that dependency actually points at
 * (respecting node_modules nesting/hoisting), and record the edge
 * instance -> requirer. Built once per graph and walked from a target
 * instance back up to the root for every finding that needs it.
 */
function buildParentIndex(graph: LockfileGraph): Map<string, ParentEdge[]> {
  const parentsOf = new Map<string, ParentEdge[]>();
  const addEdge = (childPath: string, parentPath: string) => {
    const existing = parentsOf.get(childPath);
    if (existing) existing.push({ parentPath });
    else parentsOf.set(childPath, [{ parentPath }]);
  };

  for (const [entryPath, entry] of Object.entries(graph.packages)) {
    const isRoot = entryPath === "";
    const deps: Record<string, string> = {
      ...(entry.dependencies ?? {}),
      ...(entry.optionalDependencies ?? {}),
      ...(isRoot ? entry.devDependencies ?? {} : {}),
    };
    for (const depName of Object.keys(deps)) {
      const resolved = resolveDependency(graph, entryPath, depName);
      if (resolved) addEdge(resolved, entryPath);
    }
  }
  return parentsOf;
}

function label(path: string, graph: LockfileGraph): string {
  if (path === "") return "your project";
  const entry = graph.packages[path];
  const name = packageNameAt(path, entry);
  return entry?.version ? `${name}@${entry.version}` : name;
}

/**
 * All the concrete root-to-leaf chains (up to MAX_PATHS, each up to
 * MAX_DEPTH deep) by which `packageName` ends up installed, per this
 * lockfile. A package can be reachable more than one way — via a direct
 * dependency and also nested under something else — so this returns a
 * list of paths rather than assuming there's exactly one.
 */
export function findDependencyPaths(graph: LockfileGraph, packageName: string): string[][] {
  const parentsOf = buildParentIndex(graph);

  const targets = Object.keys(graph.packages).filter(
    (p) => p !== "" && packageNameAt(p, graph.packages[p]) === packageName
  );

  const results: string[][] = [];

  function dfs(path: string, chainLeafFirst: string[], visited: Set<string>) {
    if (results.length >= MAX_PATHS) return;
    if (path === "") {
      results.push([...chainLeafFirst, "your project"].reverse());
      return;
    }
    if (chainLeafFirst.length >= MAX_DEPTH) return;

    const parents = parentsOf.get(path) ?? [];
    for (const parent of parents) {
      if (results.length >= MAX_PATHS) return;
      if (visited.has(parent.parentPath)) continue; // dependency cycle guard
      dfs(parent.parentPath, [...chainLeafFirst, label(path, graph)], new Set([...visited, parent.parentPath]));
    }
  }

  for (const target of targets) {
    if (results.length >= MAX_PATHS) break;
    dfs(target, [], new Set([target]));
  }

  return results;
}
