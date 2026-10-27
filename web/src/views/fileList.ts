import type { Session } from "../auth/session.js";
import { mountUploader, formatBytes } from "./upload.js";

interface FileRow {
  id: string;
  original_name: string;
  content_type: string;
  plaintext_size: number;
  created_at: string;
}

interface ListResponse {
  files: FileRow[];
}

function readCookie(name: string): string | null {
  const prefix = name + "=";
  for (const part of document.cookie.split(";")) {
    const trimmed = part.trim();
    if (trimmed.startsWith(prefix)) return decodeURIComponent(trimmed.slice(prefix.length));
  }
  return null;
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

  const listEl = root.querySelector<HTMLUListElement>("#files-list")!;
  const emptyEl = root.querySelector<HTMLParagraphElement>("#files-empty")!;
  const errEl = root.querySelector<HTMLParagraphElement>("#files-error")!;
  const uploadSlot = root.querySelector<HTMLDivElement>("#upload-slot")!;

  const load = async (): Promise<void> => {
    errEl.hidden = true;
    try {
      const res = await fetch("/api/files", { credentials: "same-origin" });
      if (res.status === 401) {
        location.reload();
        return;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = (await res.json()) as ListResponse;
      renderRows(body.files);
    } catch (e) {
      errEl.textContent = `Could not load files: ${(e as Error).message}`;
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
        </div>
        <div class="file-actions">
          <a class="file-download" href="#">Download</a>
          <button class="file-delete" type="button">Delete</button>
        </div>`;

      
      li.querySelector<HTMLElement>(".file-name")!.textContent = f.original_name;
      
      li.querySelector<HTMLElement>(".file-detail")!.textContent =
        `${formatBytes(f.plaintext_size)} · ${f.content_type} · ${new Date(f.created_at).toLocaleString()}`;

      const download = li.querySelector<HTMLAnchorElement>(".file-download")!;
      download.addEventListener("click", (ev) => {
        ev.preventDefault();
        window.location.href = `/api/files/${encodeURIComponent(f.id)}/download`;
      });

      const del = li.querySelector<HTMLButtonElement>(".file-delete")!;
      del.addEventListener("click", async () => {
        if (!window.confirm(`Are you sure you want to delete "${f.original_name}"?`)) {
          return;
        }
        del.disabled = true;
        try {
          const csrf = readCookie("csrf_token");
          const res = await fetch(`/api/files/${encodeURIComponent(f.id)}`, {
            method: "DELETE",
            credentials: "same-origin",
            headers: csrf ? { "X-CSRF-Token": csrf } : {},
          });
          if (!res.ok && res.status !== 404) throw new Error(`HTTP ${res.status}`);
          await load(); 
        } catch (e) {
          errEl.textContent = `Delete failed: ${(e as Error).message}`;
          errEl.hidden = false;
          del.disabled = false;
        }
      });

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