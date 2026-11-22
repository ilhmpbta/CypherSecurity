import { API_BASE } from "./config.js";

const CSRF_HEADER = "X-CSRF-Token";
const CSRF_COOKIE = "csrf_token";

let csrfToken: string | null = null;

export interface ApiError {
  code: string;
  status: number;
}

export interface RawOptions {
  method?: string;
  body?: BodyInit | null;
  contentType?: string;
}

export interface BlobResult {
  blob: Blob;
  filename: string;
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
    await fetch(`${API_BASE}/api/auth/me`, { credentials: "same-origin" });
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
  if (!headers.has("Content-Type")) headers.set("Content-Type", "application/json");

  if (method !== "GET" && method !== "HEAD") {
    headers.set(CSRF_HEADER, await ensureCsrf());
  }

  const res = await fetch(`${API_BASE}${path}`, {
    ...init,
    method,
    headers,
    credentials: "same-origin",
  });

  if (res.status === 204) return undefined as T;

  if (!res.ok) {
    let code = "unknown";
    try {
      const body = (await res.json()) as { error?: string | { code?: string } };
      if (typeof body.error === "string") {
        code = body.error;
      } else if (body.error && typeof body.error === "object" && body.error.code) {
        code = body.error.code;
      }
    } catch {
      /* non-JSON body */
    }
    throw { code, status: res.status } satisfies ApiError;
  }

  return (await res.json()) as T;
}

export async function apiFetchRaw(
  path: string,
  options: RawOptions = {},
): Promise<unknown> {
  const method = (options.method ?? "GET").toUpperCase();
  const headers = new Headers();
  if (options.contentType) headers.set("Content-Type", options.contentType);
  if (method !== "GET" && method !== "HEAD") {
    headers.set(CSRF_HEADER, await ensureCsrf());
  }
  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body: options.body ?? null,
    credentials: "same-origin",
  });
  if (res.status === 204) return undefined;
  if (!res.ok) throw await apiError(res);
  const text = await res.text();
  return text ? JSON.parse(text) as unknown : undefined;
}

export async function apiFetchBlob(path: string): Promise<BlobResult> {
  const res = await fetch(`${API_BASE}${path}`, { credentials: "same-origin" });
  if (!res.ok) throw await apiError(res);
  const disposition = res.headers.get("Content-Disposition") ?? "";
  const match = /filename="?([^";]+)"?/i.exec(disposition);
  return {
    blob: await res.blob(),
    filename: match?.[1] ?? "download",
  };
}

async function apiError(res: Response): Promise<ApiError> {
  let code = "unknown";
  try {
    const body = (await res.json()) as { error?: string | { code?: string } };
    if (typeof body.error === "string") code = body.error;
    else if (body.error && typeof body.error === "object" && body.error.code) {
      code = body.error.code;
    }
  } catch {
    /* non-JSON body */
  }
  return { code, status: res.status };
}

export function isReauth(error: unknown): boolean {
  return typeof error === "object" && error !== null &&
    (error as ApiError).status === 401 &&
    (error as ApiError).code === "reauth_required";
}

export function isSessionExpired(error: unknown): boolean {
  if (typeof error !== "object" || error === null) return false;
  const apiErrorValue = error as ApiError;
  return apiErrorValue.status === 401 &&
    (apiErrorValue.code === "session_expired" ||
      apiErrorValue.code === "unauthorized");
}