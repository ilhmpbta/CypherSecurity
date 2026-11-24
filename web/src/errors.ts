const MESSAGES: Record<string, string> = {
  // auth (handlers/auth.go)
  "invalid credentials": "Invalid username or password",
  "username already taken": "That username is already taken",
  "too many failed login attempts": "Too many attempts — please wait a moment",
  "invalid request": "Invalid request",
  "invalid request: username and password are required": "Please fill in all fields",
  "internal error": "Something went wrong on the server",

  // middleware
  "csrf token invalid": "Your session expired — please reload and try again",
  "rate limit exceeded": "Too many requests — please slow down",
  "request entity too large": "That file is too large",
  "unauthorized": "Please sign in again",

  // files (handlers/files.go)
  "invalid multipart request": "Invalid file upload",
  "missing file field": "No file was attached",
  "unsupported or mismatched file type": "That file type isn't accepted or the file contents don't match its extension",
  "file exceeds size limit": "That file is larger than the server allows",
  "upload failed": "Upload failed — please try again",
  "list failed": "Could not load your files",
  "download failed": "Download failed",
  "delete failed": "Delete failed",
  "not found": "Not found",

  // records (handlers/records.go)
  "data_type is required": "Data type is required",
  "create failed": "Could not create record",
  "update failed": "Could not update record",

  // frontend-generated (web/src/api.ts)
  csrf_unavailable: "Could not reach the server — please reload",
  reauth_required: "Your session is locked. Enter your password to continue",
  reauth_cancelled: "Password re-entry was cancelled",
  session_expired: "Please sign in again",
  invalid_transition: "This share was revoked or is no longer in the required state",
  forbidden: "You do not have permission to perform this action",
  validation_failed: "The .cskey file is invalid or has been tampered with",
  invalid_content_type: "Only PDF files can be signed",
  too_large: "That file is too large",
  conflict: "The share has changed. Refresh and try again",
  revoked: "The owner has revoked this share",
};

export function friendlyMessage(code: string): string {
  if (!code) return "Something went wrong — please try again";
  return MESSAGES[code] ?? code;
}