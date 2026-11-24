export function renderFingerprint(parent: HTMLElement, fingerprint: string): void {
  const short = fingerprint.length >= 8 ? fingerprint.slice(0, 8) : fingerprint;
  const el = document.createElement("code");
  el.textContent = short;
  el.title = fingerprint;
  el.style.fontFamily = "monospace";
  el.addEventListener("click", () => {
    void navigator.clipboard?.writeText(fingerprint);
  });
  parent.appendChild(el);
}
