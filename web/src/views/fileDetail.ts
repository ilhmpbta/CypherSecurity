import { ApiError, apiFetch, isSessionExpired } from "../api.js";
import { friendlyMessage } from "../errors.js";
import { withReauth } from "../shares/reauth.js";
import { formatBytes } from "./upload.js";
import { signFile, verifyFile } from "../pdf/pdfApi.js";
import { renderVerifyLoading, renderVerifyPanel } from "../pdf/verifyPanel.js";
import type { VerifyResponse } from "../pdf/types.js";

interface FileRow {
  id: string;
  original_name: string;
  content_type: string;
  plaintext_size: number;
  created_at: string;
  access: "owner" | "shared";
  share_state?: "none" | "pending" | "approved" | "imported" | "revoked";
}

interface ListResponse {
  files: FileRow[];
}

export function renderFileDetail(
  root: HTMLElement,
  fileId: string,
  username: string,
  onBack: () => void,
): void {
  root.innerHTML = `
    <header>
      <h2>File details</h2>
      <button id="file-detail-back" type="button">Back to files</button>
    </header>
    <p id="file-detail-loading">Loading file…</p>
    <p id="file-detail-error" role="alert" hidden></p>
    <section id="file-detail-content" hidden>
      <h3 id="file-detail-name"></h3>
      <dl>
        <dt>Content type</dt><dd id="file-detail-type"></dd>
        <dt>Size</dt><dd id="file-detail-size"></dd>
        <dt>Access</dt><dd id="file-detail-access"></dd>
        <dt>Created</dt><dd id="file-detail-created"></dd>
      </dl>
      <div id="pdf-actions" class="pdf-actions"></div>
      <p id="pdf-error" role="alert" hidden></p>
      <div id="pdf-result"></div>
    </section>
  `;

  root.querySelector<HTMLButtonElement>("#file-detail-back")!.addEventListener("click", onBack);
  const loading = root.querySelector<HTMLParagraphElement>("#file-detail-loading")!;
  const error = root.querySelector<HTMLParagraphElement>("#file-detail-error")!;
  const content = root.querySelector<HTMLElement>("#file-detail-content")!;
  const actions = root.querySelector<HTMLDivElement>("#pdf-actions")!;
  const pdfError = root.querySelector<HTMLParagraphElement>("#pdf-error")!;
  const resultPanel = root.querySelector<HTMLDivElement>("#pdf-result")!;
  let file: FileRow | undefined;
  let signButton: HTMLButtonElement | undefined;
  let verifiedResult: VerifyResponse | undefined;

  const showError = (target: HTMLElement, caught: unknown): void => {
    if (isSessionExpired(caught)) {
      location.reload();
      return;
    }
    const code = typeof caught === "object" && caught !== null
      ? (caught as ApiError).code
      : "unknown";
    target.textContent = friendlyMessage(code);
    target.hidden = false;
  };

  const verify = async (): Promise<void> => {
    if (!file) return;
    pdfError.hidden = true;
    renderVerifyLoading(resultPanel);
    try {
      verifiedResult = await verifyFile(file.id);
      renderVerifyPanel(resultPanel, verifiedResult, file.access === "owner", () => {
        void sign();
      });
      if (signButton && verifiedResult.signatures.length > 0) {
        signButton.textContent = "Add another signature";
      }
    } catch (caught) {
      resultPanel.replaceChildren();
      showError(pdfError, caught);
    }
  };

  const sign = async (): Promise<void> => {
    if (!file || !signButton) return;
    if (!window.confirm("Signing rewrites the stored PDF. Continue?")) return;
    signButton.disabled = true;
    pdfError.hidden = true;
    try {
      await withReauth(() => signFile(file!.id), username);
      await load();
      await verify();
    } catch (caught) {
      showError(pdfError, caught);
    } finally {
      if (signButton) signButton.disabled = false;
    }
  };

  const load = async (): Promise<void> => {
    loading.hidden = false;
    error.hidden = true;
    try {
      const response = await apiFetch<ListResponse>("/api/files");
      file = response.files.find((row) => row.id === fileId);
      loading.hidden = true;
      if (!file) {
        error.textContent = "Not found";
        error.hidden = false;
        return;
      }
      content.hidden = false;
      root.querySelector<HTMLElement>("#file-detail-name")!.textContent = file.original_name;
      root.querySelector<HTMLElement>("#file-detail-type")!.textContent = file.content_type;
      root.querySelector<HTMLElement>("#file-detail-size")!.textContent = formatBytes(file.plaintext_size);
      root.querySelector<HTMLElement>("#file-detail-access")!.textContent = file.access;
      root.querySelector<HTMLElement>("#file-detail-created")!.textContent =
        new Date(file.created_at).toLocaleString();
      actions.replaceChildren();
      signButton = undefined;

      const isPDF = file.content_type === "application/pdf";
      const canVerify = isPDF &&
        (file.access === "owner" || (file.access === "shared" && file.share_state === "imported"));
      if (isPDF && file.access === "owner") {
        signButton = document.createElement("button");
        signButton.type = "button";
        signButton.textContent = verifiedResult?.signatures.length
          ? "Add another signature"
          : "Sign PDF";
        signButton.addEventListener("click", () => { void sign(); });
        actions.appendChild(signButton);
      }
      if (canVerify) {
        const verifyButton = document.createElement("button");
        verifyButton.type = "button";
        verifyButton.textContent = "Verify";
        verifyButton.addEventListener("click", () => { void verify(); });
        actions.appendChild(verifyButton);
        if (!verifiedResult) await verify();
      }
    } catch (caught) {
      loading.hidden = true;
      showError(error, caught);
    }
  };

  void load();
}
