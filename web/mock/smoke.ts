const BASE_URL = process.env.BASE_URL ?? "http://localhost:4173";

type CookieJar = Map<string, string>;

function updateCookies(jar: CookieJar, headers: Headers): void {
  const setCookies = headers.getSetCookie?.() ?? [];
  for (const setCookie of setCookies) {
    const pair = setCookie.split(";")[0];
    const index = pair.indexOf("=");
    if (index >= 0) jar.set(pair.slice(0, index), pair.slice(index + 1));
  }
}

function cookieHeader(jar: CookieJar): string {
  return [...jar.entries()].map(([key, value]) => `${key}=${value}`).join("; ");
}

async function request(
  jar: CookieJar,
  path: string,
  options: RequestInit = {},
): Promise<Response> {
  const method = (options.method ?? "GET").toUpperCase();
  const headers = new Headers(options.headers);
  headers.set("Cookie", cookieHeader(jar));
  if (method !== "GET" && method !== "HEAD") {
    const csrf = jar.get("csrf_token");
    if (csrf) headers.set("X-CSRF-Token", csrf);
  }
  const response = await fetch(`${BASE_URL}${path}`, { ...options, method, headers });
  updateCookies(jar, response.headers);
  return response;
}

async function json<T>(response: Response): Promise<T> {
  return await response.json() as T;
}

async function assertError(
  response: Response,
  expectedStatus: number,
  expectedCode: string,
): Promise<void> {
  if (response.status !== expectedStatus) {
    throw new Error(`expected ${expectedStatus} ${expectedCode}, got ${response.status}`);
  }
  const body = await json<{ error?: { code?: string } }>(response);
  if (body.error?.code !== expectedCode) {
    throw new Error(`expected error ${expectedCode}, got ${body.error?.code ?? "unknown"}`);
  }
}

async function login(jar: CookieJar, username: string): Promise<void> {
  await request(jar, "/api/auth/me");
  const response = await request(jar, "/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password: "password" }),
  });
  if (!response.ok) throw new Error(`login ${username} failed: ${await response.text()}`);
}

async function main(): Promise<void> {
  const alice = new Map<string, string>();
  const bob = new Map<string, string>();

  await login(alice, "alice");
  await login(bob, "bob");
  await request(alice, "/mock/reset", { method: "POST" });

  const bobFilesResponse = await request(bob, "/api/files");
  if (!bobFilesResponse.ok) throw new Error("bob file list failed");
  const bobFiles = await json<{ files: Array<{ id: string; original_name: string }> }>(bobFilesResponse);
  const report = bobFiles.files.find((file) => file.original_name === "report.pdf");
  if (!report) throw new Error("report.pdf not found");

  const createBody = JSON.stringify({ file_id: report.id, note: "Please share" });
  const created = await request(bob, "/api/shares", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: createBody,
  });
  if (created.status !== 201) throw new Error(`request status ${created.status}`);
  const share = await json<{ id: string }>(created);

  const duplicate = await request(bob, "/api/shares", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: createBody,
  });
  if (duplicate.status !== 200) throw new Error(`duplicate status ${duplicate.status}`);

  const approve = await request(alice, `/api/shares/${share.id}/approve`, { method: "POST" });
  if (!approve.ok) throw new Error(`approve failed: ${await approve.text()}`);

  const exported = await request(alice, `/api/shares/${share.id}/export`);
  if (!exported.ok) throw new Error(`export failed: ${await exported.text()}`);
  const blob = Buffer.from(await exported.arrayBuffer());
  if (blob.subarray(0, 6).toString("ascii") !== "CSKEY\x01") throw new Error("bad blob magic");

  const tampered = Buffer.from(blob);
  tampered[0] ^= 1;
  const tamperedResponse = await request(bob, "/api/shares/import", {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream" },
    body: tampered,
  });
  await assertError(tamperedResponse, 400, "validation_failed");

  const importResponse = await request(bob, "/api/shares/import", {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream" },
    body: blob,
  });
  if (!importResponse.ok) throw new Error(`import failed: ${await importResponse.text()}`);
  const reimportResponse = await request(bob, "/api/shares/import", {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream" },
    body: blob,
  });
  if (reimportResponse.status !== 200) throw new Error(`re-import status ${reimportResponse.status}`);

  const download = await request(bob, `/api/files/${report.id}/download`);
  if (!download.ok) throw new Error(`download failed: ${await download.text()}`);
  const downloaded = Buffer.from(await download.arrayBuffer());
  if (!downloaded.equals(Buffer.from("CYPHER-PDF-DEMO-BYTES"))) throw new Error("download bytes mismatch");

  const bobOwn = bobFiles.files.find((file) => file.original_name === "bob-evidence.txt");
  if (!bobOwn) throw new Error("bob-evidence.txt not found");
  const ownRequest = await request(bob, "/api/shares", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ file_id: bobOwn.id }),
  });
  await assertError(ownRequest, 403, "forbidden");

  const revoke = await request(alice, `/api/shares/${share.id}/revoke`, { method: "POST" });
  if (!revoke.ok) throw new Error(`revoke failed: ${await revoke.text()}`);

  const postRevokeDownload = await request(bob, `/api/files/${report.id}/download`);
  await assertError(postRevokeDownload, 403, "forbidden");

  const postRevokeImport = await request(bob, "/api/shares/import", {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream" },
    body: blob,
  });
  await assertError(postRevokeImport, 409, "invalid_transition");

  console.log("CypherSecurity mock smoke flow passed");
}

void main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});
