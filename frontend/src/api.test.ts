import { describe, it, expect, beforeEach, vi } from "vitest";
import { setToken, ApiError } from "./api";

describe("setToken", () => {
  beforeEach(() => localStorage.clear());

  it("stores a token in localStorage", () => {
    setToken("abc123");
    expect(localStorage.getItem("nettle_token")).toBe("abc123");
  });

  it("removes the token when called with null", () => {
    localStorage.setItem("nettle_token", "abc123");
    setToken(null);
    expect(localStorage.getItem("nettle_token")).toBeNull();
  });
});

describe("ApiError", () => {
  it("carries the HTTP status", () => {
    const err = new ApiError(401, "Unauthorized");
    expect(err.status).toBe(401);
    expect(err.message).toBe("Unauthorized");
    expect(err).toBeInstanceOf(Error);
  });
});

describe("api.request (via api methods)", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });

  it("attaches Authorization header when token exists", async () => {
    localStorage.setItem("nettle_token", "test-token");

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ user: { id: "1", email: "a@b.com" } }), {
        status: 200,
        headers: { "content-type": "application/json" },
      })
    );

    const { api } = await import("./api");
    await api.me();

    const [, opts] = fetchSpy.mock.calls[0];
    expect((opts?.headers as Record<string, string>).Authorization).toBe("Bearer test-token");
  });

  it("throws ApiError on non-ok response", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ error: "bad request" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      })
    );

    const { api } = await import("./api");
    await expect(api.me()).rejects.toThrow(ApiError);
  });
});
