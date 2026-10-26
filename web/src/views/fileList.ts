import type { Session } from "../auth/session.js";

export function renderFileList(
  root: HTMLElement,
  session: Session,
  onLogout: () => void,
): void {
  root.innerHTML = `
    <header>
      <span>Signed in as <strong id="current-user"></strong></span>
      <button id="logout" type="button">Sign out</button>
    </header>
    <h2>Your files</h2>
    <p>File list coming in the next task.</p>`;

  const userEl = root.querySelector("#current-user");
  if (userEl) {
      userEl.textContent = session.username; 
  }
  const logoutBtn = root.querySelector<HTMLButtonElement>("#logout");
  if (logoutBtn) {
    logoutBtn.addEventListener("click", onLogout);
  }
}