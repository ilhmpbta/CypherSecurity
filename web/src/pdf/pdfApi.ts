import { apiFetch } from "../api.js";
import type { SignResponse, VerifyResponse } from "./types.js";

export function signFile(id: string): Promise<SignResponse> {
  return apiFetch<SignResponse>(`/api/files/${encodeURIComponent(id)}/sign`, {
    method: "POST",
  });
}

export function verifyFile(id: string): Promise<VerifyResponse> {
  return apiFetch<VerifyResponse>(`/api/files/${encodeURIComponent(id)}/verify`);
}
