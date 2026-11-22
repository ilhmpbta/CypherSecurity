import { ApiError, apiFetch, isReauth, isSessionExpired } from "../api.js";

let reauthBusy = false;

export function promptReauth(username: string): Promise<boolean> {
  if (reauthBusy) return Promise.resolve(false);
  reauthBusy = true;

  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.className = "reauth-overlay";
    overlay.innerHTML = `
      <section class="reauth-modal" role="dialog" aria-modal="true" aria-labelledby="reauth-title">
        <h3 id="reauth-title">Unlock your session</h3>
        <form id="reauth-form">
          <label>Password
            <input id="reauth-password" type="password" autocomplete="current-password" />
          </label>
          <p id="reauth-error" role="alert" hidden></p>
          <div class="reauth-actions">
            <button id="reauth-cancel" type="button">Cancel</button>
            <button id="reauth-submit" type="submit">Unlock</button>
          </div>
        </form>
      </section>`;
    document.body.appendChild(overlay);

    const password = overlay.querySelector<HTMLInputElement>("#reauth-password")!;
    const form = overlay.querySelector<HTMLFormElement>("form")!;
    const error = overlay.querySelector<HTMLParagraphElement>("#reauth-error")!;
    const cancel = overlay.querySelector<HTMLButtonElement>("#reauth-cancel")!;
    const submit = overlay.querySelector<HTMLButtonElement>("#reauth-submit")!;

    const close = (result: boolean): void => {
      password.value = "";
      overlay.remove();
      reauthBusy = false;
      resolve(result);
    };
    cancel.addEventListener("click", () => close(false));
    overlay.addEventListener("keydown", (event) => {
      if (event.key === "Escape") close(false);
    });

    form.addEventListener("submit", (event) => {
      event.preventDefault();
      submit.disabled = true;
      error.hidden = true;
      const entered = password.value;
      password.value = "";
      void apiFetch<unknown>("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password: entered }),
      }).then(() => {
        close(true);
      }).catch((caught: unknown) => {
        const code = typeof caught === "object" && caught !== null
          ? (caught as ApiError).code
          : "unknown";
        error.textContent = code === "invalid credentials"
          ? "Invalid username or password"
          : "Unlock failed";
        error.hidden = false;
        submit.disabled = false;
        password.focus();
      });
    });
    password.focus();
  });
}

export async function withReauth<T>(fn: () => Promise<T>, username: string): Promise<T> {
  try {
    return await fn();
  } catch (error) {
    if (isSessionExpired(error)) {
      location.reload();
      throw error;
    }
    if (!isReauth(error)) throw error;
    const unlocked = await promptReauth(username);
    if (!unlocked) throw { code: "reauth_cancelled", status: 401 } satisfies ApiError;
    return fn();
  }
}
