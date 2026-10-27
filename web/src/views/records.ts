interface PersonalRecord {
  id: string;
  data_type: string;
  payload: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

interface ListResponse {
  records: PersonalRecord[];
}

function readCookie(name: string): string | null {
  const prefix = name + "=";
  for (const part of document.cookie.split(";")) {
    const trimmed = part.trim();
    if (trimmed.startsWith(prefix)) return decodeURIComponent(trimmed.slice(prefix.length));
  }
  return null;
}

export function renderRecordsList(root: HTMLElement, onBack: () => void): void {
  root.innerHTML = `
    <header style="margin-bottom: 1.5rem;">
      <button id="back-btn" type="button">&larr; Back to Files</button>
      <h2>Personal Records</h2>
    </header>
    
    <div id="record-form-slot"></div>
    
    <p id="records-empty" hidden>No records found. Create one above.</p>
    <p id="records-error" role="alert" hidden></p>
    <ul id="records-list" class="files-list" style="margin-top: 1rem;"></ul>
  `;

  const backBtn = root.querySelector<HTMLButtonElement>("#back-btn")!;
  backBtn.addEventListener("click", onBack);

  const listEl = root.querySelector<HTMLUListElement>("#records-list")!;
  const emptyEl = root.querySelector<HTMLParagraphElement>("#records-empty")!;
  const errEl = root.querySelector<HTMLParagraphElement>("#records-error")!;
  const formSlot = root.querySelector<HTMLDivElement>("#record-form-slot")!;

  let records: PersonalRecord[] = [];

  const load = async (): Promise<void> => {
    errEl.hidden = true;
    try {
      const res = await fetch("/api/records", { credentials: "same-origin" });
      if (res.status === 401) { location.reload(); return; }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = (await res.json()) as ListResponse;
      records = body.records;
      renderRows();
    } catch (e) {
      errEl.textContent = `Could not load records: ${(e as Error).message}`;
      errEl.hidden = false;
    }
  };

  const renderRows = (): void => {
    listEl.innerHTML = "";
    if (records.length === 0) {
      emptyEl.hidden = false;
      return;
    }
    emptyEl.hidden = true;

    for (const r of records) {
      const li = document.createElement("li");
      li.className = "file-row";
      
      const payloadPreview = JSON.stringify(r.payload).substring(0, 50) + (JSON.stringify(r.payload).length > 50 ? "..." : "");

      li.innerHTML = `
        <div class="file-meta">
          <strong class="file-name">${r.data_type}</strong>
          <span class="file-detail">${payloadPreview} · ${new Date(r.created_at).toLocaleDateString()}</span>
        </div>
        <div class="file-actions">
          <button class="file-delete edit-btn" type="button" style="color: var(--text);">Edit</button>
          <button class="file-delete delete-btn" type="button">Delete</button>
        </div>
      `;

      li.querySelector<HTMLButtonElement>(".edit-btn")!.addEventListener("click", () => {
        showForm(r);
      });

      li.querySelector<HTMLButtonElement>(".delete-btn")!.addEventListener("click", async (ev) => {
        if (!confirm(`Delete record "${r.data_type}"?`)) return;
        const btn = ev.target as HTMLButtonElement;
        btn.disabled = true;
        try {
          const csrf = readCookie("csrf_token");
          const res = await fetch(`/api/records/${encodeURIComponent(r.id)}`, {
            method: "DELETE",
            credentials: "same-origin",
            headers: csrf ? { "X-CSRF-Token": csrf } : {},
          });
          if (!res.ok && res.status !== 404) throw new Error(`HTTP ${res.status}`);
          await load();
        } catch (e) {
          errEl.textContent = `Delete failed: ${(e as Error).message}`;
          errEl.hidden = false;
          btn.disabled = false;
        }
      });

      listEl.appendChild(li);
    }
  };

  const showForm = (existingRecord?: PersonalRecord): void => {
    const isEdit = !!existingRecord;
    const payloadStr = isEdit ? JSON.stringify(existingRecord.payload, null, 2) : "{\n  \n}";
    
    formSlot.innerHTML = `
      <div class="uploader" style="border-color: #555;">
        <h3>${isEdit ? "Edit Record" : "Create New Record"}</h3>
        <form id="record-form" style="margin-top: 1rem;">
          <label style="margin-bottom: 0.5rem;">
            Data Type (e.g. password, note)
            <input name="data_type" required value="${isEdit ? existingRecord.data_type : ""}" />
          </label>
          <label>
            Payload (JSON)
            <textarea name="payload" rows="5" required style="font-family: monospace; padding: 0.5rem; font-size: 0.9em; background: transparent; color: inherit; border: 1px solid #555; border-radius: 4px; resize: vertical;">${payloadStr}</textarea>
          </label>
          <p id="form-error" role="alert" hidden style="color: #c0392b; margin-top: 0.5rem;"></p>
          <div class="upload-actions" style="margin-top: 1rem;">
            <button type="button" id="cancel-form" class="file-delete">Cancel</button>
            <button type="submit">${isEdit ? "Save Changes" : "Create Record"}</button>
          </div>
        </form>
      </div>
    `;

    const form = formSlot.querySelector<HTMLFormElement>("#record-form")!;
    const err = formSlot.querySelector<HTMLParagraphElement>("#form-error")!;
    
    formSlot.querySelector<HTMLButtonElement>("#cancel-form")!.addEventListener("click", () => {
      formSlot.innerHTML = "";
    });

    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      err.hidden = true;

      const formData = new FormData(form);
      const dataType = String(formData.get("data_type") || "").trim();
      const payloadText = String(formData.get("payload") || "").trim();

      if (!dataType) {
        err.textContent = "Data type is required.";
        err.hidden = false;
        return;
      }

      let parsedPayload: Record<string, unknown>;
      try {
        parsedPayload = JSON.parse(payloadText);
        if (typeof parsedPayload !== "object" || parsedPayload === null || Array.isArray(parsedPayload)) {
          throw new Error("Payload must be a JSON object.");
        }
      } catch (e) {
        err.textContent = `Invalid JSON: ${(e as Error).message}`;
        err.hidden = false;
        return;
      }

      const submitBtn = form.querySelector<HTMLButtonElement>('button[type="submit"]')!;
      submitBtn.disabled = true;

      try {
        const csrf = readCookie("csrf_token");
        const url = isEdit ? `/api/records/${encodeURIComponent(existingRecord.id)}` : "/api/records";
        const method = isEdit ? "PATCH" : "POST";

        const res = await fetch(url, {
          method,
          credentials: "same-origin",
          headers: {
            "Content-Type": "application/json",
            ...(csrf ? { "X-CSRF-Token": csrf } : {}),
          },
          body: JSON.stringify({ data_type: dataType, payload: parsedPayload }),
        });

        if (!res.ok) {
          let msg = `HTTP ${res.status}`;
          try {
            const body = await res.json();
            if (body.error) msg = typeof body.error === "string" ? body.error : JSON.stringify(body.error);
          } catch {}
          throw new Error(msg);
        }

        formSlot.innerHTML = ""; 
        await load();
      } catch (e) {
        err.textContent = `Save failed: ${(e as Error).message}`;
        err.hidden = false;
        submitBtn.disabled = false;
      }
    });
  };

  showForm();
  void load();
}