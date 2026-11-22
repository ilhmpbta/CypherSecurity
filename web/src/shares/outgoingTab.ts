import { ApiError, apiFetchBlob } from "../api.js";
import { friendlyMessage } from "../errors.js";
import { importShare, listOutgoing } from "./api.js";
import { downloadBlob } from "./download.js";
import { renderFingerprint } from "./fingerprint.js";
import { withReauth } from "./reauth.js";
import { ShareRow } from "./types.js";

export function mountOutgoing(container: HTMLElement, username: string): () => void {
  container.innerHTML = `
    <div class="share-controls">
      <button id="outgoing-import" type="button">Import .cskey</button>
      <input id="outgoing-file" type="file" accept=".cskey" hidden />
      <label>Status
        <select id="outgoing-status">
          <option value="">All</option>
          <option value="pending">Pending</option>
          <option value="approved">Approved</option>
          <option value="rejected">Rejected</option>
          <option value="revoked">Revoked</option>
        </select>
      </label>
    </div>
    <p id="outgoing-loading">Loading…</p>
    <p id="outgoing-empty" hidden>No outgoing shares.</p>
    <p id="outgoing-error" role="alert" hidden></p>
    <ul id="outgoing-list" class="shares-list"></ul>`;

  const select = container.querySelector<HTMLSelectElement>("#outgoing-status")!;
  const importButton = container.querySelector<HTMLButtonElement>("#outgoing-import")!;
  const fileInput = container.querySelector<HTMLInputElement>("#outgoing-file")!;
  const loading = container.querySelector<HTMLParagraphElement>("#outgoing-loading")!;
  const empty = container.querySelector<HTMLParagraphElement>("#outgoing-empty")!;
  const error = container.querySelector<HTMLParagraphElement>("#outgoing-error")!;
  const list = container.querySelector<HTMLUListElement>("#outgoing-list")!;

  const showRowError = (li: HTMLLIElement, e: unknown): void => {
    let el = li.querySelector<HTMLParagraphElement>(".row-error");
    if (!el) {
      el = document.createElement("p");
      el.className = "row-error";
      el.setAttribute("role", "alert");
      li.appendChild(el);
    }
    const code = typeof e === "object" && e !== null ? (e as ApiError).code : "unknown";
    el.textContent = friendlyMessage(code);
  };

  const renderRow = (share: ShareRow): HTMLLIElement => {
    const li = document.createElement("li");
    li.className = "share-row";
    const name = document.createElement("strong");
    name.textContent = share.file_name;
    const owner = document.createElement("span");
    owner.textContent = `Owner: ${share.owner.username}`;
    const fp = document.createElement("span");
    fp.textContent = "Fingerprint: ";
    renderFingerprint(fp, share.owner.fingerprint);
    li.append(name, owner, fp);

    if (share.status === "pending") {
      const status = document.createElement("span");
      status.textContent = "Waiting for owner";
      li.appendChild(status);
    } else if (share.status === "revoked") {
      const banner = document.createElement("p");
      banner.className = "revoked-banner";
      banner.textContent = "Revoked by owner";
      li.appendChild(banner);
    } else if (share.status === "rejected") {
      const status = document.createElement("strong");
      status.textContent = "Rejected";
      li.appendChild(status);
    } else if (share.status === "approved" && !share.imported_at) {
      const status = document.createElement("span");
      status.textContent = "Waiting for key. Import the .cskey the owner sent you";
      li.appendChild(status);
    } else if (share.status === "approved" && share.imported_at) {
      const download = document.createElement("button");
      download.type = "button";
      download.textContent = "Download";
      download.addEventListener("click", async () => {
        download.disabled = true;
        try {
          const result = await withReauth(
            () => apiFetchBlob(`/api/files/${encodeURIComponent(share.file_id)}/download`),
            username,
          );
          downloadBlob(result.blob, result.filename);
        } catch (e) {
          showRowError(li, e);
        } finally {
          download.disabled = false;
        }
      });
      li.appendChild(download);
    }
    return li;
  };

  const load = async (): Promise<void> => {
    loading.hidden = false;
    empty.hidden = true;
    error.hidden = true;
    list.innerHTML = "";
    try {
      const result = await listOutgoing(select.value);
      loading.hidden = true;
      empty.hidden = result.shares.length !== 0;
      for (const share of result.shares) list.appendChild(renderRow(share));
    } catch (e) {
      loading.hidden = true;
      const code = typeof e === "object" && e !== null ? (e as ApiError).code : "unknown";
      error.textContent = friendlyMessage(code);
      error.hidden = false;
    }
  };

  importButton.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", () => {
    const file = fileInput.files?.[0];
    if (!file) return;
    if (file.size > 8 * 1024) {
      error.textContent = "The .cskey file exceeds the 8 KiB limit";
      error.hidden = false;
      fileInput.value = "";
      return;
    }
    importButton.disabled = true;
    void file.arrayBuffer().then(async (bytes) => {
      try {
        await importShare(bytes);
        error.hidden = true;
        await load();
      } catch (e) {
        const code = typeof e === "object" && e !== null ? (e as ApiError).code : "unknown";
        error.textContent = friendlyMessage(code);
        error.hidden = false;
      } finally {
        importButton.disabled = false;
        fileInput.value = "";
      }
    });
  });
  select.addEventListener("change", () => { void load(); });
  void load();
  return () => { /* hash routing remount replaces container */ };
}
