import type { Session } from "../auth/session.js";
import { mountUploader, formatBytes } from "./upload.js";
import { apiFetch, apiFetchBlob, ApiError, isSessionExpired } from "../api.js";
import { friendlyMessage } from "../errors.js";
import { requestShare } from "../shares/api.js";
import { downloadBlob } from "../shares/download.js";
import { withReauth } from "../shares/reauth.js";

interface FileRow {
  id: string;
  original_name: string;
  content_type: string;
  plaintext_size: number;
  created_at: string;
  access: "owner" | "shared";
  my_pending_request_id: string | null;
  pending_requests_count: number;
  share_state?: "none" | "pending" | "approved" | "imported" | "revoked";
}

interface ListResponse {
  files: FileRow[];
}

export function renderFileList(
  root: HTMLElement,
  session: Session,
  onLogout: () => void,
): void {
  root.innerHTML = `
    <header>
      <span>Signed in as <strong id="current-user"></strong></span>
      <div style="display: flex; gap: 0.5rem;">
        <button id="nav-records" type="button">Personal Records</button>
        <button id="nav-shares" type="button">Shares</button>
        <button id="logout" type="button">Sign out</button>
      </div>
    </header>
    <h2>Your files</h2>
    <div id="upload-slot"></div>
    <p id="files-empty" hidden>No files yet. Upload one above.</p>
    <p id="files-error" role="alert" hidden></p>
    <ul id="files-list" class="files-list"></ul>`;

  const userEl = root.querySelector<HTMLSpanElement>("#current-user");
  if (userEl) userEl.textContent = session.username;

  const logoutBtn = root.querySelector<HTMLButtonElement>("#logout");
  if (logoutBtn) logoutBtn.addEventListener("click", onLogout);

  const recordsBtn = root.querySelector<HTMLButtonElement>("#nav-records");
  if (recordsBtn) {
    recordsBtn.addEventListener("click", () => {
      location.hash = "#records";
    });
  }

  const sharesBtn = root.querySelector<HTMLButtonElement>("#nav-shares");
  sharesBtn?.addEventListener("click", () => {
    location.hash = "#shares";
  });

  const listEl = root.querySelector<HTMLUListElement>("#files-list")!;
  const emptyEl = root.querySelector<HTMLParagraphElement>("#files-empty")!;
  const errEl = root.querySelector<HTMLParagraphElement>("#files-error")!;
  const uploadSlot = root.querySelector<HTMLDivElement>("#upload-slot")!;

  const load = async (): Promise<void> => {
    errEl.hidden = true;
    try {
      const body = await apiFetch<ListResponse>("/api/files");
      renderRows(body.files);
    } catch (e) {
      if (isSessionExpired(e)) {
        location.reload();
        return;
      }
      const code = typeof e === "object" && e !== null ? (e as ApiError).code : "unknown";
      errEl.textContent = `Could not load files: ${friendlyMessage(code)}`;
      errEl.hidden = false;
    }
  };

  const renderRows = (files: FileRow[]): void => {
    listEl.innerHTML = "";
    if (files.length === 0) {
      emptyEl.hidden = false;
      return;
    }
    emptyEl.hidden = true;

    for (const f of files) {
      const li = document.createElement("li");
      li.className = "file-row";
      li.innerHTML = `
        <div class="file-meta">
          <strong class="file-name"></strong>
          <span class="file-detail"></span>
          <a class="file-details" href="#">Details</a>
        </div>
        <div class="file-actions">
          <span class="file-inline-error" role="alert" hidden></span>
        </div>`;

      
      li.querySelector<HTMLElement>(".file-name")!.textContent = f.original_name;
      
      li.querySelector<HTMLElement>(".file-detail")!.textContent =
        `${formatBytes(f.plaintext_size)} · ${f.content_type} · ${new Date(f.created_at).toLocaleString()}`;
      const details = li.querySelector<HTMLAnchorElement>(".file-details")!;
      details.href = `#file/${encodeURIComponent(f.id)}`;

      const actions = li.querySelector<HTMLElement>(".file-actions")!;
      const inlineError = li.querySelector<HTMLSpanElement>(".file-inline-error")!;

      if (f.access === "shared") {
        const shareState = f.share_state ??
          (f.my_pending_request_id ? "pending" : "none");
        if (shareState === "pending" || f.my_pending_request_id) {
          const waiting = document.createElement("span");
          waiting.textContent = "Request pending";
          actions.appendChild(waiting);
        } else if (shareState === "imported") {
          const download = document.createElement("button");
          download.type = "button";
          download.textContent = "Download";
          download.addEventListener("click", async () => {
            download.disabled = true;
            try {
              const result = await withReauth(
                () => apiFetchBlob(`/api/files/${encodeURIComponent(f.id)}/download`),
                session.username,
              );
              downloadBlob(result.blob, result.filename);
            } catch (e) {
              if (isSessionExpired(e)) {
                location.reload();
                return;
              }
              const code = typeof e === "object" && e !== null ? (e as ApiError).code : "unknown";
              inlineError.textContent = code === "forbidden"
                ? friendlyMessage("revoked")
                : friendlyMessage(code);
              inlineError.hidden = false;
            } finally {
              download.disabled = false;
            }
          });
          actions.appendChild(download);
        } else if (shareState === "approved") {
          const waiting = document.createElement("span");
          waiting.textContent = "Approved — import the .cskey in Shares";
          actions.appendChild(waiting);
        } else if (shareState === "revoked") {
          const revoked = document.createElement("span");
          revoked.textContent = "Revoked by owner";
          actions.appendChild(revoked);
        } else {
          const request = document.createElement("button");
          request.type = "button";
          request.textContent = "Request Access";
          request.addEventListener("click", async () => {
            request.disabled = true;
            try {
              await requestShare(f.id, "");
              await load();
            } catch (e) {
              if (isSessionExpired(e)) {
                location.reload();
                return;
              }
              const code = typeof e === "object" && e !== null ? (e as ApiError).code : "unknown";
              inlineError.textContent = friendlyMessage(code);
              inlineError.hidden = false;
              request.disabled = false;
            }
          });
          actions.appendChild(request);
        }
      } else {
        if (f.pending_requests_count > 0) {
          const badge = document.createElement("button");
          badge.type = "button";
          badge.textContent = `${f.pending_requests_count} pending`;
          badge.addEventListener("click", () => {
            location.hash = "#shares/inbox";
          });
          actions.appendChild(badge);
        }
        const download = document.createElement("button");
        download.type = "button";
        download.textContent = "Download";
        download.addEventListener("click", async () => {
          download.disabled = true;
          try {
            const result = await apiFetchBlob(`/api/files/${encodeURIComponent(f.id)}/download`);
            downloadBlob(result.blob, result.filename);
          } catch (e) {
            if (isSessionExpired(e)) {
              location.reload();
              return;
            }
            const code = typeof e === "object" && e !== null ? (e as ApiError).code : "unknown";
            inlineError.textContent = friendlyMessage(code);
            inlineError.hidden = false;
          } finally {
            download.disabled = false;
          }
        });
        const del = document.createElement("button");
        del.type = "button";
        del.textContent = "Delete";
        del.addEventListener("click", async () => {
          if (!window.confirm(`Are you sure you want to delete "${f.original_name}"?`)) return;
          del.disabled = true;
          try {
            await apiFetch<void>(`/api/files/${encodeURIComponent(f.id)}`, { method: "DELETE" });
            await load();
          } catch (e) {
            if (isSessionExpired(e)) {
              location.reload();
              return;
            }
            const code = typeof e === "object" && e !== null ? (e as ApiError).code : "unknown";
            inlineError.textContent = friendlyMessage(code);
            inlineError.hidden = false;
            del.disabled = false;
          }
        });
        actions.append(download, del);
      }

      listEl.appendChild(li);
    }
  };

  const teardown = mountUploader(uploadSlot, () => { void load(); });

  const observer = new MutationObserver(() => {
    if (!root.contains(uploadSlot)) {
      teardown();
      observer.disconnect();
    }
  });
  observer.observe(root, { childList: true, subtree: true });

  void load();
}