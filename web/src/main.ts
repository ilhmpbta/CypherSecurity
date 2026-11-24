import { renderLogin } from "./auth/login.js";
import { renderRegister } from "./auth/register.js";
import { currentSession, logout } from "./auth/session.js";
import type { Session } from "./auth/session.js";
import { renderFileList } from "./views/fileList.js";
import { renderRecordsList } from "./views/records.js";
import { renderSharesPage } from "./shares/sharesPage.js";
import { renderFileDetail } from "./views/fileDetail.js";

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

  if (location.hash === "#records") {
    renderRecordsList(root!, () => {
      location.hash = "";
    });
  } else if (location.hash === "#shares" || location.hash.startsWith("#shares/")) {
    renderSharesPage(root!, session.username, () => {
      location.hash = "";
    });
  } else if (location.hash.startsWith("#file/")) {
    const fileId = decodeURIComponent(location.hash.slice("#file/".length));
    renderFileDetail(root!, fileId, session.username, () => {
      location.hash = "";
    });
  } else {
    renderFileList(root!, session, () => {
      void logout();
    });
  }
}

window.addEventListener("hashchange", () => {
  void boot();
});

void boot();