import { mountInbox } from "./inboxTab.js";
import { mountOutgoing } from "./outgoingTab.js";

export function renderSharesPage(root: HTMLElement, username: string, onBack: () => void): void {
  root.innerHTML = `
    <header>
      <h2>Shares</h2>
      <button id="shares-back" type="button">Back to files</button>
    </header>
    <nav class="share-tabs" aria-label="Share views">
      <button id="tab-inbox" type="button">Inbox</button>
      <button id="tab-outgoing" type="button">Outgoing</button>
    </nav>
    <section id="shares-content"></section>`;

  root.querySelector<HTMLButtonElement>("#shares-back")!.addEventListener("click", onBack);
  const content = root.querySelector<HTMLElement>("#shares-content")!;
  const inbox = root.querySelector<HTMLButtonElement>("#tab-inbox")!;
  const outgoing = root.querySelector<HTMLButtonElement>("#tab-outgoing")!;

  const activate = (): void => {
    const outgoingActive = location.hash === "#shares/outgoing";
    inbox.classList.toggle("active", !outgoingActive);
    outgoing.classList.toggle("active", outgoingActive);
    content.innerHTML = "";
    if (outgoingActive) mountOutgoing(content, username);
    else mountInbox(content, username);
  };

  inbox.addEventListener("click", () => {
    location.hash = "#shares/inbox";
  });
  outgoing.addEventListener("click", () => {
    location.hash = "#shares/outgoing";
  });
  activate();
}
