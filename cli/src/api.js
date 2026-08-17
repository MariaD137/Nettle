import { getToken, getApiUrl } from "./config.js";

/**
 * Make an authenticated JSON request to the Nettle API.
 */
export async function request(method, path, { body, apiUrl, headers: extraHeaders } = {}) {
  const baseUrl = getApiUrl(apiUrl);
  const url = `${baseUrl}${path}`;

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
