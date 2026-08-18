import { test } from "node:test";
import assert from "node:assert/strict";
import { parseLockfileGraph, findDependencyPaths } from "../src/scanner/lockfileGraph";

test("parseLockfileGraph returns null for invalid JSON", () => {
  assert.equal(parseLockfileGraph("{not json"), null);
});

test("parseLockfileGraph returns null for a lockfileVersion 1 style lockfile (no flat packages map)", () => {
  const v1 = JSON.stringify({
    name: "old-app",
    lockfileVersion: 1,
    dependencies: { foo: { version: "1.0.0" } },
  });
  assert.equal(parseLockfileGraph(v1), null);
});

test("findDependencyPaths resolves a direct dependency", () => {
  const graph = parseLockfileGraph(
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "test-app", dependencies: { "vulnerable-lib": "^2.0.0" } },
        "node_modules/vulnerable-lib": { version: "2.1.0" },
      },
    })
  )!;

  const paths = findDependencyPaths(graph, "vulnerable-lib");
  assert.deepEqual(paths, [["your project", "vulnerable-lib@2.1.0"]]);
});

test("findDependencyPaths resolves a transitive dependency nested under a direct one", () => {
  const graph = parseLockfileGraph(
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "test-app", dependencies: { wrapper: "^1.0.0" } },
        "node_modules/wrapper": { version: "1.0.0", dependencies: { "vulnerable-lib": "^2.0.0" } },
        "node_modules/vulnerable-lib": { version: "2.1.0" },
      },
    })
  )!;

  const paths = findDependencyPaths(graph, "vulnerable-lib");
  assert.deepEqual(paths, [["your project", "wrapper@1.0.0", "vulnerable-lib@2.1.0"]]);
});

test("findDependencyPaths reports both routes when a package is installed at two locations (hoisted + nested)", () => {
  const graph = parseLockfileGraph(
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "test-app", dependencies: { a: "^1.0.0", b: "^1.0.0" } },
        "node_modules/a": { version: "1.0.0", dependencies: { target: "^1.0.0" } },
        // b needs an incompatible major of target, so npm nests a private copy under b
        // instead of hoisting it — the hoisted node_modules/target instance is a's.
        "node_modules/b": { version: "1.0.0", dependencies: { target: "^2.0.0" } },
        "node_modules/target": { version: "1.0.0" },
        "node_modules/b/node_modules/target": { version: "2.0.0" },
      },
    })
  )!;

  const paths = findDependencyPaths(graph, "target").map((p) => p.join(" > "));
  assert.equal(paths.length, 2);
  assert.ok(paths.includes("your project > a@1.0.0 > target@1.0.0"));
  assert.ok(paths.includes("your project > b@1.0.0 > target@2.0.0"));
});

test("findDependencyPaths returns an empty array for a package that isn't in the lockfile", () => {
  const graph = parseLockfileGraph(
    JSON.stringify({
      lockfileVersion: 3,
      packages: { "": { dependencies: {} } },
    })
  )!;
  assert.deepEqual(findDependencyPaths(graph, "nothing-here"), []);
});

test("findDependencyPaths terminates on a dependency cycle instead of hanging or duplicating paths", () => {
  // a requires b, b requires a — both resolve back to the same hoisted
  // node_modules/a instance, a genuine (if unusual) shape npm's graph can
  // take with peer-style circular requires.
  const graph = parseLockfileGraph(
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "test-app", dependencies: { a: "^1.0.0" } },
        "node_modules/a": { version: "1.0.0", dependencies: { b: "^1.0.0" } },
        "node_modules/b": { version: "1.0.0", dependencies: { a: "^1.0.0" } },
      },
    })
  )!;

  const paths = findDependencyPaths(graph, "a");
  assert.deepEqual(paths, [["your project", "a@1.0.0"]]);
});

test("scoped package names resolve correctly through nested node_modules paths", () => {
  const graph = parseLockfileGraph(
    JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "test-app", dependencies: { "@scope/wrapper": "^1.0.0" } },
        "node_modules/@scope/wrapper": { version: "1.0.0", dependencies: { "@scope/vulnerable": "^2.0.0" } },
        "node_modules/@scope/wrapper/node_modules/@scope/vulnerable": { version: "2.1.0" },
      },
    })
  )!;

  const paths = findDependencyPaths(graph, "@scope/vulnerable");
  assert.deepEqual(paths, [["your project", "@scope/wrapper@1.0.0", "@scope/vulnerable@2.1.0"]]);
});
