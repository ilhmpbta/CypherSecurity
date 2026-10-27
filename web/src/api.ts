const CSRF_HEADER = "X-CSRF-Token";
const CSRF_COOKIE = "csrf_token";

let csrfToken: string | null = null;

export interface ApiError {
  code: string;
  status: number;
}

function readCookie(name: string): string | null {
  const prefix = name + "=";
  for (const part of document.cookie.split(";")) {
    const trimmed = part.trim();
    if (trimmed.startsWith(prefix)) return decodeURIComponent(trimmed.slice(prefix.length));
  }
  return null;
}

async function ensureCsrf(): Promise<string> {
  if (csrfToken) return csrfToken;

  const fromCookie = readCookie(CSRF_COOKIE);
  if (fromCookie) {
    csrfToken = fromCookie;
    return csrfToken;
  }

  try {
    await fetch("/api/auth/me", { credentials: "same-origin" });
  } catch {
    throw { code: "csrf_unavailable", status: 0 } satisfies ApiError;
  }

  const retry = readCookie(CSRF_COOKIE);
  if (!retry) throw { code: "csrf_unavailable", status: 0 } satisfies ApiError;
  csrfToken = retry;
  return csrfToken;
}

export async function apiFetch<T>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");

  if (method !== "GET" && method !== "HEAD") {
    headers.set(CSRF_HEADER, await ensureCsrf());
  }

  const res = await fetch(path, {
    ...init,
    method,
    headers,
    credentials: "same-origin",
  });

  if (res.status === 204) return undefined as T;

  if (!res.ok) {
    let code = "unknown";
    try {
      const body = (await res.json()) as { error?: { code?: string } | string };
      if (typeof body.error === "string") code = body.error;
      else if (body.error?.code) code = body.error.code;
    } catch {
      /* non-JSON body */
    }
    throw { code, status: res.status } satisfies ApiError;
  }

  return (await res.json()) as T;
}