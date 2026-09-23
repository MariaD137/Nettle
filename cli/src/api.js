import { getToken, getApiUrl } from "./config.js";

/**
 * Every call site still passes a literal "/api/..." path — this rewrites it
 * to the versioned "/api/v1/..." surface at the one place requests actually
 * go out, so none of them needed touching individually. The backend keeps
 * serving the unversioned path unchanged indefinitely (see backend's
 * middleware/apiVersion.ts), so an older CLI build talking to a newer
 * server still works.
 */
function apiPath(path) {
  return path.startsWith("/api/") ? `/api/v1/${path.slice("/api/".length)}` : path;
}

/**
 * Make an authenticated JSON request to the Nettle API.
 */
export async function request(method, path, { body, apiUrl, headers: extraHeaders } = {}) {
  const baseUrl = getApiUrl(apiUrl);
  const url = `${baseUrl}${apiPath(path)}`;

  const headers = { ...extraHeaders };

  const token = getToken();
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const opts = { method, headers };

  if (body !== undefined && !(body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  } else if (body instanceof FormData) {
    // Let fetch set the Content-Type with the boundary
    opts.body = body;
  }

  const res = await fetch(url, opts);

  // 204 No Content
  if (res.status === 204) {
    return { ok: true, status: 204, data: null };
  }

  let data;
  try {
    data = await res.json();
  } catch {
    data = null;
  }

  if (!res.ok) {
    const message = data?.error || `Request failed with status ${res.status}`;
    const err = new Error(message);
    err.status = res.status;
    err.data = data;
    throw err;
  }

  return { ok: true, status: res.status, data };
}
