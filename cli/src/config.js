import fs from "fs";
import path from "path";
import os from "os";

const CONFIG_DIR = path.join(os.homedir(), ".nettle");
const CONFIG_FILE = path.join(CONFIG_DIR, "config.json");

const DEFAULT_API_URL = "http://localhost:8080";

function ensureConfigDir() {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
  }
}

export function readConfig() {
  try {
    const raw = fs.readFileSync(CONFIG_FILE, "utf-8");
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

// mode: 0o600 — this file holds the session token in plaintext (see
// setToken below). Without an explicit mode, Node creates it at the
// platform default (typically 0o666 minus umask, so world/group-readable
// under a permissive umask), which on a shared machine would let any other
// local user read another user's live Nettle session token straight off
// disk. chmod on every write, not just creation, so an already-existing
// file from before this fix — or one an old CLI version left looser — gets
// tightened too.
function writeConfigFile(data) {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(data, null, 2) + "\n", { encoding: "utf-8", mode: 0o600 });
  fs.chmodSync(CONFIG_FILE, 0o600);
}

export function writeConfig(data) {
  ensureConfigDir();
  const existing = readConfig();
  const merged = { ...existing, ...data };
  writeConfigFile(merged);
}

export function getToken() {
  return readConfig().token || null;
}

export function setToken(token) {
  writeConfig({ token });
}

export function removeToken() {
  const config = readConfig();
  delete config.token;
  ensureConfigDir();
  writeConfigFile(config);
}

export function getApiUrl(override) {
  if (override) return override.replace(/\/+$/, "");
  const config = readConfig();
  return (config.apiUrl || DEFAULT_API_URL).replace(/\/+$/, "");
}
