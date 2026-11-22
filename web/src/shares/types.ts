export type ShareStatus = "pending" | "approved" | "rejected" | "revoked";

export interface ShareIdentity {
  id: string;
  username: string;
  fingerprint: string;
}

export interface ShareRow {
  id: string;
  file_id: string;
  file_name: string;
  owner: ShareIdentity;
  requester: ShareIdentity;
  status: ShareStatus;
  note: string | null;
  requested_at: string;
  decided_at: string | null;
  delivered_at: string | null;
  imported_at: string | null;
  revoked_at: string | null;
}

export interface ShareListResponse {
  shares: ShareRow[];
}
