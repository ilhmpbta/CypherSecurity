import { apiFetch, ApiError } from "../api.js";
import { friendlyMessage } from "../errors.js";
import type { Session } from "./session.js";

export function renderLogin(root: HTMLElement, onSuccess: () => void): void {
  root.innerHTML = `
    <form id="login" novalidate>
      <h2>Sign in</h2>
      <label>Username <input name="username" autocomplete="username" required></label>
      <label>Password <input name="password" type="password" autocomplete="current-password" required></label>
      <button type="submit">Sign in</button>
      <p id="login-error" role="alert" hidden></p>
      <p><a href="#register">Create an account</a></p>
    </form>`;

  const form = root.querySelector<HTMLFormElement>("#login")!;
  const errEl = root.querySelector<HTMLParagraphElement>("#login-error")!;

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    errEl.hidden = true;

    const data = new FormData(form);
    const username = String(data.get("username") ?? "").trim();
    const password = String(data.get("password") ?? "");

    if (!username || !password) {
      errEl.textContent = "Please fill in both fields";
      errEl.hidden = false;
      return;
    }

    try {
      await apiFetch<Session>("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      await apiFetch<Session>("/api/me");
      onSuccess();
    } catch (e) {
      const code = (e as ApiError).code ?? "unknown";
      errEl.textContent = friendlyMessage(code);
      errEl.hidden = false;
    }
  });
  
  const registerLink = root.querySelector<HTMLAnchorElement>('a[href="#register"]');
  if (registerLink) {
    registerLink.addEventListener("click", (e) => {
      e.preventDefault(); 
      location.hash = "#register"; 
    });
  }
}