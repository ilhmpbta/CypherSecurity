import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PORT = Number(process.env.PORT ?? 4173);
const MOCK_SECRET = "cyphersecurity-mock-secret";
const HERE = path.dirname(fileURLToPath(import.meta.url));
const DIST = path.resolve(HERE, "..", "dist");

interface User {
  id: string;
  username: string;
  password: string;
  fingerprint: string;
}

interface FileRow {
  id: string;
  original_name: string;
  content_type: string;
  plaintext_size: number;
  created_at: string;
  owner_id: string;
  bytes: Buffer;
}

interface ShareRow {
  id: string;
  file_id: string;
  file_name: string;
  owner: { id: string; username: string; fingerprint: string };
  requester: { id: string; username: string; fingerprint: string };
  status: "pending" | "approved" | "rejected" | "revoked";
  note: string | null;
  requested_at: string;
  decided_at: string | null;
  delivered_at: string | null;
  imported_at: string | null;
  revoked_at: string | null;
}

interface Session {
  userId: string;
  wrapKey: Buffer | null;
  csrf: string;
}

const users: User[] = [
  { id: "11111111-1111-4111-8111-111111111111", username: "alice", password: "password",
    fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
  { id: "22222222-2222-4222-8222-222222222222", username: "bob", password: "password",
    fingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
];

const files = new Map<string, FileRow>([
  ["f1111111-1111-4111-8111-111111111111", {
    id: "f1111111-1111-4111-8111-111111111111",
    original_name: "report.pdf", content_type: "application/pdf",
    plaintext_size: 21, created_at: "2026-10-27T10:00:00Z",
    owner_id: users[0].id, bytes: Buffer.from("CYPHER-PDF-DEMO-BYTES"),
  }],
  ["f2222222-2222-4222-8222-222222222222", {
    id: "f2222222-2222-4222-8222-222222222222",
    original_name: "notes.txt", content_type: "text/plain",
    plaintext_size: 20, created_at: "2026-10-27T10:05:00Z",
    owner_id: users[0].id, bytes: Buffer.from("Alice confidential notes"),
  }],
  ["f3333333-3333-4333-8333-333333333333", {
    id: "f3333333-3333-4333-8333-333333333333",
    original_name: "bob-evidence.txt", content_type: "text/plain",
    plaintext_size: 18, created_at: "2026-10-27T10:10:00Z",
    owner_id: users[1].id, bytes: Buffer.from("Bob evidence demo."),
  }],
]);

const sessions = new Map<string, Session>();
const shares = new Map<string, ShareRow>();
let nextFile = 4000;

function userById(id: string): User | undefined {
  return users.find((user) => user.id === id);
}

function readCookie(header: string | undefined, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) return rest.join("=");
  }
  return undefined;
}

function sessionFor(req: http.IncomingMessage): Session | undefined {
  const cookie = readCookie(req.headers.cookie, "session");
  return cookie ? sessions.get(cookie) : undefined;
}

function setCookie(res: http.ServerResponse, name: string, value: string, httpOnly = false): void {
  res.setHeader("Set-Cookie", [
    ...(Array.isArray(res.getHeader("Set-Cookie")) ? res.getHeader("Set-Cookie") as string[] : []),
    `${name}=${value}; Path=/; SameSite=Lax${httpOnly ? "; HttpOnly" : ""}`,
  ]);
}

function error(res: http.ServerResponse, status: number, code: string): void {
  json(res, status, { error: { code } });
}

function guardKeys(value: unknown): boolean {
  if (Array.isArray(value)) return value.every(guardKeys);
  if (!value || typeof value !== "object") return true;
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (/^(dek|wrapped_key|wrapped|private|wrapkey|cert_der)$/i.test(key)) return false;
    if (!guardKeys(child)) return false;
  }
  return true;
}

function json(res: http.ServerResponse, status: number, body: unknown): void {
  if (!guardKeys(body)) {
    res.statusCode = 500;
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ error: { code: "internal_error" } }));
    return;
  }
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(body));
}

async function readBody(req: http.IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return Buffer.concat(chunks);
}

function uuidBytes(id: string): Buffer {
  const hex = id.replace(/-/g, "").padEnd(32, "0").slice(0, 32);
  return Buffer.from(hex, "hex");
}

function makeUuid(): string {
  return crypto.randomUUID();
}

function buildBlob(share: ShareRow): Buffer {
  const header = Buffer.alloc(108);
  header.write("CSKEY", 0, "ascii");
  header.writeUInt8(1, 5);
  header.writeUInt8(1, 6);
  uuidBytes(share.id).copy(header, 7);
  uuidBytes(share.file_id).copy(header, 23);
  header.writeUInt8(32, 39);
  Buffer.from(share.owner.fingerprint, "hex").copy(header, 40);
  header.writeUInt8(32, 72);
  Buffer.from(share.requester.fingerprint, "hex").copy(header, 73);
  header.writeUInt8(1, 105);
  const wrappedKey = crypto.createHash("sha256").update(`${share.id}:${share.file_id}:${MOCK_SECRET}`).digest();
  header.writeUInt16BE(wrappedKey.length, 106);
  const signed = Buffer.concat([header, wrappedKey]);
  const signature = crypto.createHmac("sha256", MOCK_SECRET).update(signed).digest();
  const trailer = Buffer.alloc(2);
  trailer.writeUInt16BE(signature.length);
  return Buffer.concat([signed, trailer, signature]);
}

function verifyBlob(blob: Buffer, share: ShareRow): boolean {
  if (blob.length < 112) return false;
  if (blob.subarray(0, 6).toString("ascii") !== "CSKEY\x01") return false;
  if (blob.readUInt8(6) !== 1) return false;
  const n = blob.readUInt16BE(106);
  if (n < 1 || n > 4096) return false;
  const payloadEnd = 108 + n;
  if (payloadEnd + 2 > blob.length) return false;
  const m = blob.readUInt16BE(payloadEnd);
  if (payloadEnd + 2 + m !== blob.length) return false;
  const ownerFp = blob.subarray(40, 72).toString("hex");
  const requesterFp = blob.subarray(73, 105).toString("hex");
  if (blob.readUInt8(39) !== 32 || blob.readUInt8(72) !== 32) return false;
  if (ownerFp !== share.owner.fingerprint || requesterFp !== share.requester.fingerprint) return false;
  if (blob.readUInt8(105) !== 1) return false;
  const requestId = blob.subarray(7, 23).toString("hex");
  const fileId = blob.subarray(23, 39).toString("hex");
  if (requestId !== uuidBytes(share.id).toString("hex")) return false;
  if (fileId !== uuidBytes(share.file_id).toString("hex")) return false;
  const expected = crypto.createHmac("sha256", MOCK_SECRET).update(blob.subarray(0, payloadEnd)).digest();
  return crypto.timingSafeEqual(expected, blob.subarray(payloadEnd + 2));
}

function publicShare(row: ShareRow): ShareRow {
  return { ...row };
}

function activeShare(userId: string, fileId: string): ShareRow | undefined {
  return [...shares.values()].find((share) =>
    share.requester.id === userId &&
    share.file_id === fileId &&
    share.status === "approved" &&
    share.imported_at !== null &&
    share.revoked_at === null);
}

function requireCsrf(req: http.IncomingMessage, res: http.ServerResponse, session: Session | undefined): boolean {
  if (!session) return false;
  const supplied = req.headers["x-csrf-token"];
  if (typeof supplied !== "string" || supplied !== session.csrf) {
    error(res, 403, "csrf token invalid");
    return false;
  }
  return true;
}

function sendStatic(reqUrl: URL, res: http.ServerResponse): void {
  let relative = reqUrl.pathname === "/" ? "index.html" : reqUrl.pathname.slice(1);
  relative = path.normalize(relative).replace(/^(\.\.(\/|\\|$))+/, "");
  const candidate = path.resolve(DIST, relative);
  if (!candidate.startsWith(DIST)) {
    res.statusCode = 403;
    res.end();
    return;
  }
  fs.readFile(candidate, (readError, data) => {
    if (readError) {
      res.statusCode = 404;
      res.end("Not found");
      return;
    }
    const ext = path.extname(candidate).toLowerCase();
    res.setHeader("Content-Type",
      ext === ".html" ? "text/html; charset=utf-8" :
      ext === ".js" ? "text/javascript" :
      ext === ".css" ? "text/css" : "application/octet-stream");
    res.statusCode = 200;
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  const reqUrl = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
  const pathname = reqUrl.pathname;
  const method = (req.method ?? "GET").toUpperCase();

  if (!pathname.startsWith("/api/") && !pathname.startsWith("/mock/")) {
    sendStatic(reqUrl, res);
    return;
  }

  if (pathname.startsWith("/mock/")) {
    if (pathname === "/mock/lock" && method === "POST") {
      const session = sessionFor(req);
      if (!session) { error(res, 401, "session_expired"); return; }
      session.wrapKey = null;
      json(res, 200, { locked: true });
      return;
    }
    if (pathname === "/mock/reset" && method === "POST") {
      shares.clear();
      for (const session of sessions.values()) session.wrapKey = Buffer.alloc(32, 7);
      json(res, 200, { reset: true });
      return;
    }
  }

  const session = sessionFor(req);

  if (pathname === "/api/auth/me" && method === "GET") {
    if (!session) {
      const csrf = crypto.randomBytes(16).toString("hex");
      setCookie(res, "csrf_token", csrf);
      error(res, 401, "session_expired");
      return;
    }
    const user = userById(session.userId);
    setCookie(res, "csrf_token", session.csrf);
    json(res, 200, { id: user?.id, username: user?.username });
    return;
  }

  if ((pathname === "/api/auth/login" || pathname === "/api/auth/register") && method === "POST") {
    if (method === "POST" && session && !requireCsrf(req, res, session)) return;
    if (!session) {
      const cookieId = crypto.randomBytes(16).toString("hex");
      // unauthenticated login starts with a csrf cookie established by GET /auth/me
      if (!readCookie(req.headers.cookie, "csrf_token")) {
        error(res, 403, "csrf token invalid");
        return;
      }
      const csrf = readCookie(req.headers.cookie, "csrf_token")!;
      const suppliedCsrf = req.headers["x-csrf-token"];
      if (typeof suppliedCsrf !== "string" || suppliedCsrf !== csrf) {
        error(res, 403, "csrf token invalid");
        return;
      }
      const body = JSON.parse((await readBody(req)).toString("utf8")) as { username?: string; password?: string };
      let user = users.find((candidate) => candidate.username === body.username && candidate.password === body.password);
      if (pathname === "/api/auth/register" && body.username && body.password) {
        const existing = users.find((candidate) => candidate.username === body.username);
        if (existing) { error(res, 409, "conflict"); return; }
        const fingerprint = crypto.createHash("sha256").update(body.username).digest("hex").padEnd(64, "0").slice(0, 64);
        user = {
          id: makeUuid(),
          username: body.username,
          password: body.password,
          fingerprint,
        };
        users.push(user);
      }
      if (!user) { error(res, 401, "session_expired"); return; }
      sessions.set(cookieId, { userId: user.id, wrapKey: Buffer.alloc(32, 7), csrf });
      setCookie(res, "session", cookieId, true);
      setCookie(res, "csrf_token", csrf);
      json(res, 200, { id: user.id, username: user.username });
      return;
    }
    const body = JSON.parse((await readBody(req)).toString("utf8")) as { username?: string; password?: string };
    const user = users.find((candidate) => candidate.username === body.username && candidate.password === body.password);
    if (!user || user.id !== session.userId) { error(res, 401, "invalid credentials"); return; }
    session.wrapKey = Buffer.alloc(32, 7);
    setCookie(res, "csrf_token", session.csrf);
    json(res, 200, { id: user.id, username: user.username });
    return;
  }

  if (pathname === "/api/auth/logout" && method === "POST") {
    if (!session || !requireCsrf(req, res, session)) { if (!session) error(res, 401, "session_expired"); return; }
    const cookie = readCookie(req.headers.cookie, "session");
    if (cookie) sessions.delete(cookie);
    json(res, 200, {});
    return;
  }

  if (!session) { error(res, 401, "session_expired"); return; }

  if (pathname === "/api/files" && method === "GET") {
    const current = userById(session.userId)!;
    const result = [...files.values()].map((file) => {
      const owned = file.owner_id === current.id;
      const pending = [...shares.values()].find((share) =>
        share.requester.id === current.id && share.file_id === file.id && share.status === "pending");
      const shareRow = [...shares.values()].find((share) =>
        share.requester.id === current.id && share.file_id === file.id &&
        share.status !== "rejected");
      let shareState: "none" | "pending" | "approved" | "imported" | "revoked" = "none";
      if (shareRow) {
        if (shareRow.revoked_at) shareState = "revoked";
        else if (shareRow.imported_at) shareState = "imported";
        else if (shareRow.status === "approved") shareState = "approved";
        else if (shareRow.status === "pending") shareState = "pending";
      }
      const pendingRequestsCount = owned
        ? [...shares.values()].filter((share) => share.file_id === file.id && share.status === "pending").length
        : 0;
      return {
        id: file.id, original_name: file.original_name, content_type: file.content_type,
        plaintext_size: file.bytes.length, created_at: file.created_at,
        access: owned ? "owner" : "shared",
        my_pending_request_id: pending?.id ?? null,
        pending_requests_count: pendingRequestsCount,
        share_state: owned ? "none" : shareState,
      };
    });
    json(res, 200, { files: result });
    return;
  }

  if (pathname === "/api/files" && method === "POST") {
    if (!requireCsrf(req, res, session)) return;
    const body = await readBody(req);
    const contentType = req.headers["content-type"] ?? "";
    let name = "uploaded.bin";
    if (contentType.includes("multipart/form-data")) {
      const match = /filename="([^"]+)"/.exec(body.toString("latin1"));
      if (match) name = match[1];
    }
    nextFile++;
    const id = `f${nextFile.toString(16).padStart(32, "0")}`;
    files.set(id, {
      id, original_name: name, content_type: contentType.includes("multipart") ? "application/octet-stream" : "application/octet-stream",
      plaintext_size: body.length, created_at: new Date().toISOString(), owner_id: session.userId,
      bytes: body,
    });
    json(res, 201, { id, original_name: name });
    return;
  }

  const fileMatch = pathname.match(/^\/api\/files\/([^/]+)(.*)$/);
  if (fileMatch) {
    const fileId = decodeURIComponent(fileMatch[1]);
    const suffix = fileMatch[2];
    const file = files.get(fileId);
    if (!file) { error(res, 404, "not_found"); return; }

    if (suffix === "" && method === "DELETE") {
      if (!requireCsrf(req, res, session)) return;
      if (file.owner_id !== session.userId) { error(res, 403, "forbidden"); return; }
      files.delete(fileId);
      json(res, 200, { deleted: true });
      return;
    }

    if (suffix === "/download" && method === "GET") {
      if (file.owner_id === session.userId) {
        res.setHeader("Content-Type", file.content_type);
        res.setHeader("Content-Disposition", `attachment; filename="${file.original_name}"`);
        res.statusCode = 200;
        res.end(file.bytes);
        return;
      }
      const share = activeShare(session.userId, fileId);
      if (!share) { error(res, 403, "forbidden"); return; }
      if (!session.wrapKey) { error(res, 401, "reauth_required"); return; }
      res.setHeader("Content-Type", file.content_type);
      res.setHeader("Content-Disposition", `attachment; filename="${file.original_name}"`);
      res.statusCode = 200;
      res.end(file.bytes);
      return;
    }

    if (suffix === "/sign" && method === "POST") {
      if (!requireCsrf(req, res, session)) return;
      if (file.owner_id !== session.userId) { error(res, 403, "forbidden"); return; }
      if (file.content_type !== "application/pdf" && !file.original_name.toLowerCase().endsWith(".pdf")) {
        error(res, 400, "invalid_content_type"); return;
      }
      if (!session.wrapKey) { error(res, 401, "reauth_required"); return; }
      json(res, 200, { signed: true, status: "valid" });
      return;
    }

    if (suffix === "/verify" && method === "GET") {
      if (file.owner_id !== session.userId && !activeShare(session.userId, fileId)) {
        error(res, 403, "forbidden"); return;
      }
      const statusByFile: Record<string, string> = {
        "f1111111-1111-4111-8111-111111111111": "valid",
      };
      const status = statusByFile[fileId] ?? "no_signature";
      json(res, 200, {
        status,
        signer: status === "valid" ? {
          username: "alice",
          fingerprint: users[0].fingerprint,
        } : null,
        certificate: status === "valid" ? { subject: "CN=alice", expires_at: "2027-10-27T10:00:00Z" } : null,
      });
      return;
    }
  }

  if (pathname === "/api/shares" && method === "POST") {
    if (!requireCsrf(req, res, session)) return;
    const body = JSON.parse((await readBody(req)).toString("utf8")) as { file_id?: string; note?: string };
    const file = body.file_id ? files.get(body.file_id) : undefined;
    if (!file) { error(res, 404, "not_found"); return; }
    if (file.owner_id === session.userId) { error(res, 403, "forbidden"); return; }
    const existing = [...shares.values()].find((share) =>
      share.file_id === file.id && share.requester.id === session.userId && share.status === "pending");
    if (existing) { json(res, 200, publicShare(existing)); return; }
    const owner = userById(file.owner_id)!;
    const requester = userById(session.userId)!;
    const row: ShareRow = {
      id: makeUuid(), file_id: file.id, file_name: file.original_name,
      owner: { id: owner.id, username: owner.username, fingerprint: owner.fingerprint },
      requester: { id: requester.id, username: requester.username, fingerprint: requester.fingerprint },
      status: "pending", note: body.note ?? null,
      requested_at: new Date().toISOString(), decided_at: null, delivered_at: null,
      imported_at: null, revoked_at: null,
    };
    shares.set(row.id, row);
    json(res, 201, publicShare(row));
    return;
  }

  if ((pathname === "/api/shares/inbox" || pathname === "/api/shares/outgoing") && method === "GET") {
    const statusFilter = reqUrl.searchParams.get("status");
    const rows = [...shares.values()].filter((share) =>
      pathname.endsWith("/inbox")
        ? share.owner.id === session.userId
        : share.requester.id === session.userId);
    const filtered = statusFilter ? rows.filter((share) => share.status === statusFilter) : rows;
    json(res, 200, { shares: filtered.map(publicShare) });
    return;
  }

  const shareMatch = pathname.match(/^\/api\/shares\/([^/]+)\/(approve|reject|revoke|export)$/);
  if (shareMatch) {
    const shareId = decodeURIComponent(shareMatch[1]);
    const suffix = `/${shareMatch[2]}`;
    const share = shares.get(shareId);
    if (!share) { error(res, 404, "not_found"); return; }

    if (suffix === "/approve" && method === "POST") {
      if (!requireCsrf(req, res, session)) return;
      if (share.owner.id !== session.userId) { error(res, 403, "forbidden"); return; }
      if (share.status !== "pending") { error(res, 409, "invalid_transition"); return; }
      if (!session.wrapKey) { error(res, 401, "reauth_required"); return; }
      share.status = "approved";
      share.decided_at = new Date().toISOString();
      json(res, 200, publicShare(share));
      return;
    }
    if (suffix === "/reject" && method === "POST") {
      if (!requireCsrf(req, res, session)) return;
      if (share.owner.id !== session.userId) { error(res, 403, "forbidden"); return; }
      if (share.status !== "pending") { error(res, 409, "invalid_transition"); return; }
      share.status = "rejected";
      share.decided_at = new Date().toISOString();
      json(res, 200, publicShare(share));
      return;
    }
    if (suffix === "/revoke" && method === "POST") {
      if (!requireCsrf(req, res, session)) return;
      if (share.owner.id !== session.userId) { error(res, 403, "forbidden"); return; }
      if (share.status !== "approved") { error(res, 409, "invalid_transition"); return; }
      share.status = "revoked";
      share.revoked_at = new Date().toISOString();
      share.decided_at ??= share.revoked_at;
      json(res, 200, publicShare(share));
      return;
    }
    if (suffix === "/export" && method === "GET") {
      if (share.owner.id !== session.userId) { error(res, 403, "forbidden"); return; }
      if (share.status !== "approved" || share.revoked_at) { error(res, 409, "invalid_transition"); return; }
      if (!session.wrapKey) { error(res, 401, "reauth_required"); return; }
      share.delivered_at = new Date().toISOString();
      const blob = buildBlob(share);
      res.statusCode = 200;
      res.setHeader("Content-Type", "application/octet-stream");
      res.setHeader("Content-Disposition", `attachment; filename="${share.file_name}.cskey"`);
      res.end(blob);
      return;
    }
  }

  if (pathname === "/api/shares/import" && method === "POST") {
    if (!requireCsrf(req, res, session)) return;
    const blob = await readBody(req);
    if (blob.length < 112) { error(res, 400, "validation_failed"); return; }
    const n = blob.length >= 108 ? blob.readUInt16BE(106) : 0;
    let shareId = "";
    try {
      shareId = blob.subarray(7, 23).toString("hex");
      const possible = [...shares.values()].find((share) => uuidBytes(share.id).toString("hex") === shareId);
      if (!possible) { error(res, 404, "not_found"); return; }
      if (possible.requester.id !== session.userId) { error(res, 403, "forbidden"); return; }
      if (possible.revoked_at || possible.status === "revoked") { error(res, 409, "invalid_transition"); return; }
      if (!verifyBlob(blob, possible)) { error(res, 400, "validation_failed"); return; }
      if (possible.imported_at) { json(res, 200, publicShare(possible)); return; }
      possible.imported_at = new Date().toISOString();
      json(res, 200, publicShare(possible));
    } catch {
      void n;
      error(res, 400, "validation_failed");
    }
    return;
  }

  error(res, 404, "not_found");
});

server.listen(PORT, () => {
  console.log(`CypherSecurity mock listening on http://localhost:${PORT}`);
});
