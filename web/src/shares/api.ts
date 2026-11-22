import { apiFetch, apiFetchBlob, apiFetchRaw, BlobResult } from "../api.js";
import { ShareListResponse, ShareRow } from "./types.js";

export function listInbox(status: string): Promise<ShareListResponse> {
  const suffix = status ? `?status=${encodeURIComponent(status)}` : "";
  return apiFetch<ShareListResponse>(`/api/shares/inbox${suffix}`);
}

export function listOutgoing(status: string): Promise<ShareListResponse> {
  const suffix = status ? `?status=${encodeURIComponent(status)}` : "";
  return apiFetch<ShareListResponse>(`/api/shares/outgoing${suffix}`);
}

export function approveShare(id: string): Promise<ShareRow> {
  return apiFetch<ShareRow>(`/api/shares/${encodeURIComponent(id)}/approve`, { method: "POST" });
}

export function rejectShare(id: string): Promise<ShareRow> {
  return apiFetch<ShareRow>(`/api/shares/${encodeURIComponent(id)}/reject`, { method: "POST" });
}

export function revokeShare(id: string): Promise<ShareRow> {
  return apiFetch<ShareRow>(`/api/shares/${encodeURIComponent(id)}/revoke`, { method: "POST" });
}

export function exportShare(id: string): Promise<BlobResult> {
  return apiFetchBlob(`/api/shares/${encodeURIComponent(id)}/export`);
}

export function importShare(blob: ArrayBuffer): Promise<unknown> {
  return apiFetchRaw("/api/shares/import", {
    method: "POST",
    body: blob,
    contentType: "application/octet-stream",
  });
}

export function requestShare(fileId: string, note: string): Promise<ShareRow> {
  return apiFetch<ShareRow>("/api/shares", {
    method: "POST",
    body: JSON.stringify({ file_id: fileId, note }),
  });
}
