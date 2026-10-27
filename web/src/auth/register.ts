import { apiFetch, ApiError } from "../api.js";
import { friendlyMessage } from "../errors.js";

interface RegisteredUser {
  id: string;
  username: string;
}

export function renderRegister(root: HTMLElement, onSuccess: () => void): void {
  root.innerHTML = `
    <form id="register" novalidate>
      <h2>Create account</h2>
      <label>Username <input name="username" autocomplete="username" required></label>
      <label>Password <input name="password" type="password" autocomplete="new-password" required></label>
      <label>Confirm password <input name="confirm" type="password" autocomplete="new-password" required></label>
      <button type="submit">Create account</button>
      <p id="register-error" role="alert" hidden></p>
      <p><a href="#login">Already have an account?</a></p>
    </form>`;

  const form = root.querySelector<HTMLFormElement>("#register")!;
  const errEl = root.querySelector<HTMLParagraphElement>("#register-error")!;

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    errEl.hidden = true;

    const data = new FormData(form);
    const username = String(data.get("username") ?? "").trim();
    const password = String(data.get("password") ?? "");
    const confirm = String(data.get("confirm") ?? "");

    if (!username || !password) {
      errEl.textContent = "Please fill in all fields";
      errEl.hidden = false;
      return;
    }
    if (password !== confirm) {
      errEl.textContent = "Passwords do not match";
      errEl.hidden = false;
      return;
    }

    try {
      await apiFetch<RegisteredUser>("/api/auth/register", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      await apiFetch<RegisteredUser>("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      onSuccess();
    } catch (e) {
      const code = (e as ApiError).code ?? "unknown";
      errEl.textContent = friendlyMessage(code);
      errEl.hidden = false;
    }
  });

  const loginLink = root.querySelector<HTMLAnchorElement>('a[href="#login"]');
  if (loginLink) {
    loginLink.addEventListener("click", (e) => {
      e.preventDefault();
      location.hash = ""; 
    });
  }
}