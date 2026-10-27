import { apiFetch } from "../api.js";

export interface Session {
  id: string;
  username: string;
}

export function currentSession(): Promise<Session> {
  return apiFetch<Session>("/api/auth/me");
}

export async function logout(): Promise<void> {
  await apiFetch<void>("/api/auth/logout", { method: "POST" });
  location.reload();
}