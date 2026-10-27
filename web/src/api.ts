const CSRF_HEADER = "X-CSRF-Token";

let csrfToken: string | null = null;

export interface ApiError {
  code: string;
  status: number;
}

async function ensureCsrf(): Promise<string> {
  if (csrfToken) return csrfToken;
  const res = await fetch("/api/auth/csrf", { credentials: "same-origin" });
  if (!res.ok) throw { code: "csrf_unavailable", status: res.status } satisfies ApiError;
  const body = (await res.json()) as { csrfToken: string };
  csrfToken = body.csrfToken;
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
      const body = (await res.json()) as { error?: { code?: string } };
      if (body.error?.code) code = body.error.code;
    } catch {
      /* non-JSON body */
    }
    throw { code, status: res.status } satisfies ApiError;
  }

  return (await res.json()) as T;
}