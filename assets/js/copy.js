// "Copy" buttons for short values such as the email address: <button data-copy="value" hidden>.
// They stay hidden without JS or without the Clipboard API.
import { announce } from "./util.js";

export function initCopy() {
  const buttons = document.querySelectorAll("button[data-copy]");
  if (!buttons.length || !navigator.clipboard?.writeText) return;
  for (const btn of buttons) {
    const label = btn.textContent;
    if (btn.dataset.copyLabel) btn.setAttribute("aria-label", btn.dataset.copyLabel);
    let timer;
    btn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(btn.dataset.copy);
        btn.textContent = "Copied";
        announce("Copied to the clipboard");
      } catch {
        btn.textContent = "Failed";
        announce("Copying failed");
      }
      clearTimeout(timer);
      timer = setTimeout(() => (btn.textContent = label), 1500);
    });
    btn.hidden = false;
  }
}
