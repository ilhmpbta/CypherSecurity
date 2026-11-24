export interface SignResponse {
  file_id: string;
  signature_count: number;
  signed_at: string;
  signer_fingerprint: string;
}

export type VerifyReason = "content_modified" | "unknown_signer" | "no_signature" | null;
export type SignatureReason = "content_modified" | "unknown_signer" | null;

export interface VerifySignature {
  valid: boolean;
  reason: SignatureReason;
  signer: {
    user_id: string | null;
    username: string | null;
    fingerprint: string;
  };
  signed_at: string;
  certificate: {
    subject: string;
    issuer: string;
    serial: string;
    not_before: string;
    not_after: string;
  };
}

export interface VerifyResponse {
  signed: boolean;
  valid: boolean;
  reason: VerifyReason;
  signatures: VerifySignature[];
}
