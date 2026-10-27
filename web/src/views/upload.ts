const MAX_UPLOAD_BYTES = 32 * 1024 * 1024;

const ACCEPTED_TYPES: readonly string[] = [
  "application/pdf",
  "application/msword",
  "application/vnd.ms-excel",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "image/jpeg",
  "image/png",
  "image/webp",
  "image/heic",
  "video/mp4",
  "video/webm",
  "video/quicktime",
];

const ACCEPT_ATTR =
  ".pdf,.doc,.docx,.xls,.xlsx,.jpg,.jpeg,.png,.webp,.heic,.mp4,.webm,.mov";

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GiB`;
}

function readCookie(name: string): string | null {
  const prefix = name + "=";
  for (const part of document.cookie.split(";")) {
    const trimmed = part.trim();
    if (trimmed.startsWith(prefix)) return decodeURIComponent(trimmed.slice(prefix.length));
  }
  return null;
}

export function mountUploader(
  container: HTMLElement,
  onUploaded: () => void,
): () => void {
  container.innerHTML = `
    <section class="uploader" aria-labelledby="upload-heading">
      <h3 id="upload-heading">Upload a file</h3>
      <div class="dropzone" id="dropzone" tabindex="0" role="button"
           aria-describedby="dropzone-hint dropzone-types">
        <p class="dropzone-hint" id="dropzone-hint">
          Drag a file here, or <span class="linkish">browse</span>.
        </p>
        <p class="dropzone-types" id="dropzone-types"></p>
      </div>
      <input type="file" id="file-input" hidden />
      <div id="upload-preview" class="upload-preview" hidden>
        <div class="upload-preview-row"><strong>Name:</strong> <span id="preview-name"></span></div>
        <div class="upload-preview-row"><strong>Size:</strong> <span id="preview-size"></span></div>
        <div class="upload-preview-row"><strong>Type:</strong> <span id="preview-type"></span></div>
        <div class="upload-actions">
          <button type="button" id="upload-cancel">Cancel</button>
          <button type="button" id="upload-start">Upload</button>
        </div>
      </div>
      <div id="upload-progress-wrap" class="upload-progress" hidden>
        <div class="upload-progress-bar" role="progressbar"
             aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"
             id="upload-progress-bar">
          <div id="upload-progress-fill"></div>
        </div>
        <p id="upload-progress-label" class="upload-progress-label"></p>
      </div>
      <p id="upload-error" role="alert" hidden></p>
      <p id="upload-success" role="status" hidden></p>
    </section>`;

  const dropzone = container.querySelector<HTMLDivElement>("#dropzone")!;
  const fileInput = container.querySelector<HTMLInputElement>("#file-input")!;
  const typesHint = container.querySelector<HTMLParagraphElement>("#dropzone-types")!;
  const preview = container.querySelector<HTMLDivElement>("#upload-preview")!;
  const previewName = container.querySelector<HTMLSpanElement>("#preview-name")!;
  const previewSize = container.querySelector<HTMLSpanElement>("#preview-size")!;
  const previewType = container.querySelector<HTMLSpanElement>("#preview-type")!;
  const progressWrap = container.querySelector<HTMLDivElement>("#upload-progress-wrap")!;
  const progressBar = container.querySelector<HTMLDivElement>("#upload-progress-bar")!;
  const progressFill = container.querySelector<HTMLDivElement>("#upload-progress-fill")!;
  const progressLabel = container.querySelector<HTMLParagraphElement>("#upload-progress-label")!;
  const errEl = container.querySelector<HTMLParagraphElement>("#upload-error")!;
  const okEl = container.querySelector<HTMLParagraphElement>("#upload-success")!;
  const startBtn = container.querySelector<HTMLButtonElement>("#upload-start")!;
  const cancelBtn = container.querySelector<HTMLButtonElement>("#upload-cancel")!;

  fileInput.accept = ACCEPT_ATTR;
  typesHint.textContent =
    `Accepted: PDF, Word, Excel, JPEG, PNG, WebP, HEIC, MP4, WebM, MOV — max ${formatBytes(MAX_UPLOAD_BYTES)}`;

  let selectedFile: File | null = null;
  let xhr: XMLHttpRequest | null = null;

  const showError = (msg: string): void => {
    okEl.hidden = true;
    errEl.textContent = msg;
    errEl.hidden = false;
  };
  const clearError = (): void => { errEl.hidden = true; };
  const showSuccess = (msg: string): void => {
    errEl.hidden = true;
    okEl.textContent = msg;
    okEl.hidden = false;
  };
  const clearSuccess = (): void => { okEl.hidden = true; };

  const reset = (): void => {
    selectedFile = null;
    preview.hidden = true;
    progressWrap.hidden = true;
    progressFill.style.width = "0%";
    progressBar.setAttribute("aria-valuenow", "0");
    progressLabel.textContent = "";
    startBtn.disabled = false;
    cancelBtn.disabled = false;
    fileInput.value = "";
  };

  const reject = (msg: string): void => {
    reset();
    showError(msg);
  };

  const acceptFile = (file: File): void => {
    clearError();
    clearSuccess();

    if (file.size > MAX_UPLOAD_BYTES) {
      reject(
        `“${file.name}” is ${formatBytes(file.size)}; the limit is ${formatBytes(MAX_UPLOAD_BYTES)}.`,
      );
      return;
    }
    if (file.size === 0) {
      reject("That file is empty.");
      return;
    }
    if (file.type && !(ACCEPTED_TYPES as readonly string[]).includes(file.type)) {
      reject(`“${file.type}” is not a supported type.`);
      return;
    }

    selectedFile = file;
    previewName.textContent = file.name;
    previewSize.textContent = formatBytes(file.size);
    previewType.textContent = file.type || "(unknown — will be sniffed server-side)";
    preview.hidden = false;
  };

  const openPicker = (): void => { fileInput.click(); };

  dropzone.addEventListener("click", openPicker);
  dropzone.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter" || ev.key === " ") {
      ev.preventDefault();
      openPicker();
    }
  });

  fileInput.addEventListener("change", () => {
    const f = fileInput.files?.[0];
    if (f) acceptFile(f);
  });

  let dragDepth = 0;
  const onDragEnter = (ev: DragEvent): void => {
    ev.preventDefault();
    dragDepth++;
    dropzone.classList.add("dropzone-active");
  };
  const onDragOver = (ev: DragEvent): void => { ev.preventDefault(); };
  const onDragLeave = (ev: DragEvent): void => {
    ev.preventDefault();
    dragDepth = Math.max(0, dragDepth - 1);
    if (dragDepth === 0) dropzone.classList.remove("dropzone-active");
  };
  const onDrop = (ev: DragEvent): void => {
    ev.preventDefault();
    dragDepth = 0;
    dropzone.classList.remove("dropzone-active");
    const f = ev.dataTransfer?.files?.[0];
    if (f) acceptFile(f);
  };
  dropzone.addEventListener("dragenter", onDragEnter);
  dropzone.addEventListener("dragover", onDragOver);
  dropzone.addEventListener("dragleave", onDragLeave);
  dropzone.addEventListener("drop", onDrop);

  cancelBtn.addEventListener("click", () => {
    reset();
    clearError();
  });

  startBtn.addEventListener("click", () => {
    if (!selectedFile) return;
    clearError();
    clearSuccess();

    startBtn.disabled = true;
    cancelBtn.disabled = true;
    preview.hidden = true;
    progressWrap.hidden = false;
    progressFill.style.width = "0%";
    progressBar.setAttribute("aria-valuenow", "0");
    progressLabel.textContent = "Starting…";

    const file = selectedFile;
    const req = new XMLHttpRequest();
    xhr = req;
    req.open("POST", "/api/files", true);
    req.withCredentials = true;

    const csrf = readCookie("csrf_token");
    if (csrf) req.setRequestHeader("X-CSRF-Token", csrf);

    req.upload.onprogress = (ev) => {
      if (!ev.lengthComputable) return;
      const pct = Math.round((ev.loaded / ev.total) * 100);
      progressFill.style.width = `${pct}%`;
      progressBar.setAttribute("aria-valuenow", String(pct));
      progressLabel.textContent = `${pct}% — ${formatBytes(ev.loaded)} of ${formatBytes(ev.total)}`;
    };

        req.onload = () => {
      xhr = null;
      if (req.status >= 200 && req.status < 300) {
        progressFill.style.width = "100%";
        progressBar.setAttribute("aria-valuenow", "100");
        progressLabel.textContent = "Uploaded — refreshing list…";
        onUploaded();
        window.setTimeout(() => { progressWrap.hidden = true; }, 600);
        showSuccess(`“${file.name}” uploaded.`);
        reset();
      } else {
        progressWrap.hidden = true;
        let msg = `Upload failed (HTTP ${req.status}).`;
        try {
          const body = JSON.parse(req.responseText);
          if (typeof body.error === "string") msg = body.error;
          else if (body.error) msg = JSON.stringify(body.error);
          else msg = req.responseText || msg;
        } catch {
          msg = req.responseText || msg;
        }
        showError(msg);
        reset();
      }
    };

    req.onerror = () => {
      xhr = null;
      progressWrap.hidden = true;
      showError("Network error during upload.");
      reset();
    };

    req.onabort = () => {
      xhr = null;
      progressWrap.hidden = true;
      showError("Upload cancelled.");
      reset();
    };

    const form = new FormData();
    form.append("file", file, file.name);
    req.send(form);
  });

  return () => {
    if (xhr) { xhr.abort(); xhr = null; }
    dropzone.removeEventListener("dragenter", onDragEnter);
    dropzone.removeEventListener("dragover", onDragOver);
    dropzone.removeEventListener("dragleave", onDragLeave);
    dropzone.removeEventListener("drop", onDrop);
  };
}