import fs from "fs";
import path from "path";
import os from "os";

const CONFIG_DIR = path.join(os.homedir(), ".nettle");
const CONFIG_FILE = path.join(CONFIG_DIR, "config.json");

const DEFAULT_API_URL = "http://localhost:8080";

function ensureConfigDir() {
  if (!fs.existsSync(CONFIG_DIR)) {
    fs.mkdirSync(CONFIG_DIR, { recursive: true });
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

export function writeConfig(data) {
  ensureConfigDir();
  const existing = readConfig();
  const merged = { ...existing, ...data };
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(merged, null, 2) + "\n", "utf-8");
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
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2) + "\n", "utf-8");
}

export function getApiUrl(override) {
  if (override) return override.replace(/\/+$/, "");
  const config = readConfig();
  return (config.apiUrl || DEFAULT_API_URL).replace(/\/+$/, "");
}
