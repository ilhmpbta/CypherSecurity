import { ApiError, isSessionExpired } from "../api.js";
import { friendlyMessage } from "../errors.js";
import { approveShare, exportShare, listInbox, rejectShare, revokeShare } from "./api.js";
import { downloadBlob } from "./download.js";
import { renderFingerprint } from "./fingerprint.js";
import { withReauth } from "./reauth.js";
import { ShareRow } from "./types.js";

function formatTime(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "";
}

export function mountInbox(container: HTMLElement, username: string): () => void {
  container.innerHTML = `
    <div class="share-controls">
      <label>Status
        <select id="inbox-status">
          <option value="">All</option>
          <option value="pending">Pending</option>
          <option value="approved">Approved</option>
          <option value="rejected">Rejected</option>
          <option value="revoked">Revoked</option>
        </select>
      </label>
    </div>
    <p id="inbox-loading">Loading…</p>
    <p id="inbox-empty" hidden>No share requests.</p>
    <p id="inbox-error" role="alert" hidden></p>
    <ul id="inbox-list" class="shares-list"></ul>`;

  const select = container.querySelector<HTMLSelectElement>("#inbox-status")!;
  const loading = container.querySelector<HTMLParagraphElement>("#inbox-loading")!;
  const empty = container.querySelector<HTMLParagraphElement>("#inbox-empty")!;
  const error = container.querySelector<HTMLParagraphElement>("#inbox-error")!;
  const list = container.querySelector<HTMLUListElement>("#inbox-list")!;

  const showRowError = (li: HTMLLIElement, e: unknown): void => {
    if (isSessionExpired(e)) {
      location.reload();
      return;
    }
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
    const requester = document.createElement("span");
    requester.textContent = `Requester: ${share.requester.username}`;
    const fp = document.createElement("span");
    fp.textContent = "Fingerprint: ";
    renderFingerprint(fp, share.requester.fingerprint);
    const time = document.createElement("span");
    time.className = "share-detail";
    time.textContent = `Requested ${formatTime(share.requested_at)}`;
    li.append(name, requester, fp, time);
    if (share.note) {
      const note = document.createElement("span");
      note.textContent = `Note: ${share.note}`;
      li.appendChild(note);
    }

    const actions = document.createElement("div");
    actions.className = "share-actions";
    li.appendChild(actions);

    if (share.status === "pending") {
      const approve = document.createElement("button");
      approve.type = "button";
      approve.textContent = "Approve";
      const reject = document.createElement("button");
      reject.type = "button";
      reject.textContent = "Reject";
      approve.addEventListener("click", async () => {
        approve.disabled = true; reject.disabled = true;
        try {
          await withReauth(() => approveShare(share.id), username);
          await load();
        } catch (e) {
          showRowError(li, e);
          approve.disabled = false; reject.disabled = false;
        }
      });
      reject.addEventListener("click", async () => {
        approve.disabled = true; reject.disabled = true;
        try { await rejectShare(share.id); await load(); }
        catch (e) { showRowError(li, e); approve.disabled = false; reject.disabled = false; }
      });
      actions.append(approve, reject);
    } else if (share.status === "approved") {
      const exported = document.createElement("button");
      exported.type = "button";
      exported.textContent = "Export .cskey";
      const revoke = document.createElement("button");
      revoke.type = "button";
      revoke.textContent = "Revoke";
      exported.addEventListener("click", async () => {
        exported.disabled = true; revoke.disabled = true;
        try {
          const result = await withReauth(() => exportShare(share.id), username);
          downloadBlob(result.blob, result.filename);
        } catch (e) {
          showRowError(li, e);
        } finally {
          exported.disabled = false; revoke.disabled = false;
        }
      });
      revoke.addEventListener("click", async () => {
        if (!window.confirm(`Revoke access to "${share.file_name}"?`)) return;
        exported.disabled = true; revoke.disabled = true;
        try { await revokeShare(share.id); await load(); }
        catch (e) { showRowError(li, e); exported.disabled = false; revoke.disabled = false; }
      });
      actions.append(exported, revoke);
    } else {
      const status = document.createElement("strong");
      status.textContent = share.status === "rejected" ? "Rejected" : "Revoked";
      actions.appendChild(status);
    }
    return li;
  };

  const load = async (): Promise<void> => {
    loading.hidden = false;
    empty.hidden = true;
    error.hidden = true;
    list.innerHTML = "";
    try {
      const result = await listInbox(select.value);
      loading.hidden = true;
      empty.hidden = result.shares.length !== 0;
      for (const share of result.shares) list.appendChild(renderRow(share));
    } catch (e) {
      loading.hidden = true;
      if (isSessionExpired(e)) {
        location.reload();
        return;
      }
      const code = typeof e === "object" && e !== null ? (e as ApiError).code : "unknown";
      error.textContent = friendlyMessage(code);
      error.hidden = false;
    }
  };

  select.addEventListener("change", () => { void load(); });
  void load();
  return () => { /* hash routing remount replaces container */ };
}
