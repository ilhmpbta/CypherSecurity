import { renderFingerprint } from "../shares/fingerprint.js";
import type { VerifyReason, VerifyResponse, VerifySignature } from "./types.js";

const REASON_MESSAGES: Record<Exclude<VerifyReason, null>, string> = {
  content_modified: "The file was changed after it was signed",
  unknown_signer: "The signer's key isn't recognised",
  no_signature: "This PDF has no signature",
};

function appendText(parent: HTMLElement, label: string, value: string): void {
  const line = document.createElement("p");
  line.textContent = `${label}: ${value}`;
  parent.appendChild(line);
}

function renderSignature(signature: VerifySignature): HTMLLIElement {
  const item = document.createElement("li");
  item.className = "pdf-signature";
  const status = document.createElement("strong");
  status.textContent = signature.valid ? "Valid signature" : "Invalid signature";
  item.appendChild(status);
  if (!signature.valid && signature.reason) {
    const reason = document.createElement("p");
    reason.className = "pdf-invalid-banner";
    reason.setAttribute("role", "alert");
    reason.textContent = REASON_MESSAGES[signature.reason];
    item.appendChild(reason);
  }

  const signer = document.createElement("p");
  signer.textContent = "Signer: ";
  renderFingerprint(signer, signature.signer.fingerprint);
  if (signature.signer.username) {
    signer.appendChild(document.createTextNode(` (${signature.signer.username})`));
  }
  item.appendChild(signer);
  appendText(item, "Signed", new Date(signature.signed_at).toLocaleString());
  appendText(item, "Certificate subject", signature.certificate.subject);
  appendText(item, "Certificate issuer", signature.certificate.issuer);
  appendText(item, "Certificate expires", new Date(signature.certificate.not_after).toLocaleString());

  if (Date.parse(signature.certificate.not_after) < Date.now()) {
    const warning = document.createElement("p");
    warning.className = "pdf-cert-warning";
    warning.textContent = "Warning: this certificate has expired.";
    item.appendChild(warning);
  }
  return item;
}

export function renderVerifyPanel(
  container: HTMLElement,
  result: VerifyResponse,
  isOwner: boolean,
  onSign: () => void,
): void {
  container.replaceChildren();
  const panel = document.createElement("section");
  panel.className = "pdf-verify-panel";

  if (result.valid) {
    const badge = document.createElement("p");
    badge.className = "pdf-valid-badge";
    badge.textContent = "Signed · Valid";
    panel.appendChild(badge);
  } else {
    const reason = result.reason ?? "no_signature";
    const banner = document.createElement("p");
    banner.className = "pdf-invalid-banner";
    banner.setAttribute("role", "alert");
    banner.textContent = REASON_MESSAGES[reason];
    panel.appendChild(banner);
    if (reason === "no_signature" && isOwner) {
      const sign = document.createElement("button");
      sign.type = "button";
      sign.textContent = "Sign this PDF";
      sign.addEventListener("click", onSign);
      panel.appendChild(sign);
    }
  }

  if (result.signatures.length) {
    const list = document.createElement("ul");
    list.className = "pdf-signatures";
    for (const signature of result.signatures) list.appendChild(renderSignature(signature));
    panel.appendChild(list);
  }

  const caption = document.createElement("p");
  caption.className = "pdf-trust-caption";
  caption.textContent =
    "Self-signed certificate: confirms integrity and key binding, not a trusted CA identity.";
  panel.appendChild(caption);
  container.appendChild(panel);
}

export function renderVerifyLoading(container: HTMLElement): void {
  container.replaceChildren();
  const loading = document.createElement("p");
  loading.textContent = "Verifying PDF…";
  container.appendChild(loading);
}
