import { renderLogin } from "./auth/login.js";
import { renderRegister } from "./auth/register.js";
import { currentSession, logout } from "./auth/session.js";
import type { Session } from "./auth/session.js";
import { renderFileList } from "./views/fileList.js";

const root = document.getElementById("app");
if (!root) {
  throw new Error("root element #app not found");
}

export async function boot(): Promise<void> {
  root!.innerHTML = ""; 

  let session: Session | null = null;
  try {
    session = await currentSession();
  } catch {
    /* 401 — not logged in */
  }

  if (!session) {
    if (location.hash === "#register") {
      renderRegister(root!, () => {
        location.hash = "";
        void boot();
      });
    } else {
      renderLogin(root!, () => {
        location.hash = "";
        void boot();
      });
    }
    return;
  }

  renderFileList(root!, session, () => {
    void logout();
  });
}

window.addEventListener("hashchange", () => {
  void boot();
});

void boot();