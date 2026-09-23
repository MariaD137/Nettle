// NETTLE_DB_PATH=:memory: is set by the `test` npm script — see the comment
// in patrol.test.ts for why an in-file assignment doesn't work.
import { test } from "node:test";
import assert from "node:assert/strict";
import { resolveDatabaseUrl, assertProductionPersistence } from "../src/db";

// Covers the fix in infra/lib/api-stack.ts (Phase I): App Runner can't put a
// composite DATABASE_URL through runtimeEnvironmentSecrets (that mechanism
// substitutes a whole env var with one whole secret JSON key's value, so it
// can't interpolate a "postgresql://" prefix and hostname around two secret
// fields) without leaking the resolved RDS password into App Runner's own
// service configuration via runtimeEnvironmentVariables instead. The CDK
// stack now delivers DB_USERNAME/DB_PASSWORD through runtimeEnvironmentSecrets
// and DB_HOST/DB_PORT/DB_NAME as plain values — resolveDatabaseUrl assembles
// the real connection string here, inside the container, from those parts.

test("resolveDatabaseUrl prefers DATABASE_URL when set directly", () => {
  const url = resolveDatabaseUrl({
    DATABASE_URL: "postgresql://user:pass@localhost:5432/nettle",
    DB_HOST: "should-be-ignored",
  } as NodeJS.ProcessEnv);
  assert.equal(url, "postgresql://user:pass@localhost:5432/nettle");
});

test("resolveDatabaseUrl assembles a connection string from discrete DB_* parts", () => {
  const url = resolveDatabaseUrl({
    DB_HOST: "nettle-db.abc123.us-east-1.rds.amazonaws.com",
    DB_USERNAME: "nettle_app",
    DB_PASSWORD: "s3cret",
  } as NodeJS.ProcessEnv);
  assert.equal(url, "postgresql://nettle_app:s3cret@nettle-db.abc123.us-east-1.rds.amazonaws.com:5432/nettle");
});

test("resolveDatabaseUrl respects DB_PORT and DB_NAME overrides", () => {
  const url = resolveDatabaseUrl({
    DB_HOST: "localhost",
    DB_USERNAME: "u",
    DB_PASSWORD: "p",
    DB_PORT: "5433",
    DB_NAME: "custom_db",
  } as NodeJS.ProcessEnv);
  assert.equal(url, "postgresql://u:p@localhost:5433/custom_db");
});

test("resolveDatabaseUrl URL-encodes credentials that contain reserved characters", () => {
  const url = resolveDatabaseUrl({
    DB_HOST: "localhost",
    DB_USERNAME: "user@name",
    DB_PASSWORD: "p@ss:word/with#reserved?chars",
  } as NodeJS.ProcessEnv);
  assert.equal(
    url,
    `postgresql://user%40name:${encodeURIComponent("p@ss:word/with#reserved?chars")}@localhost:5432/nettle`
  );
  // And the assembled URL must actually parse back to the intended host and
  // round-trip the original credential — the whole point of encoding is
  // that a credential can never be mistaken for part of the host/port/path.
  const parsed = new URL(url);
  assert.equal(parsed.hostname, "localhost");
  assert.equal(decodeURIComponent(parsed.username), "user@name");
  assert.equal(decodeURIComponent(parsed.password), "p@ss:word/with#reserved?chars");
});

test("resolveDatabaseUrl returns undefined when neither DATABASE_URL nor complete DB_* parts are set", () => {
  assert.equal(resolveDatabaseUrl({} as NodeJS.ProcessEnv), undefined);
  assert.equal(resolveDatabaseUrl({ DB_HOST: "localhost" } as NodeJS.ProcessEnv), undefined);
  assert.equal(
    resolveDatabaseUrl({ DB_HOST: "localhost", DB_USERNAME: "u" } as NodeJS.ProcessEnv),
    undefined
  );
});

test("assertProductionPersistence throws in production with no DATABASE_URL and no DB_* parts", () => {
  assert.throws(
    () => assertProductionPersistence({ NODE_ENV: "production" } as NodeJS.ProcessEnv),
    /DATABASE_URL is not set/
  );
});

test("assertProductionPersistence does not throw in production with DATABASE_URL set", () => {
  assert.doesNotThrow(() =>
    assertProductionPersistence({
      NODE_ENV: "production",
      DATABASE_URL: "postgresql://user:pass@localhost:5432/nettle",
    } as NodeJS.ProcessEnv)
  );
});

test("assertProductionPersistence does not throw in production with discrete DB_* parts set (the App Runner path)", () => {
  assert.doesNotThrow(() =>
    assertProductionPersistence({
      NODE_ENV: "production",
      DB_HOST: "nettle-db.rds.amazonaws.com",
      DB_USERNAME: "nettle_app",
      DB_PASSWORD: "s3cret",
    } as NodeJS.ProcessEnv)
  );
});

test("assertProductionPersistence never throws outside production", () => {
  assert.doesNotThrow(() => assertProductionPersistence({ NODE_ENV: "development" } as NodeJS.ProcessEnv));
  assert.doesNotThrow(() => assertProductionPersistence({} as NodeJS.ProcessEnv));
});
