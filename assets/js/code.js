// Copy buttons for code blocks (figure.code). Hidden entirely when the Clipboard API is missing.
import { announce } from "./util.js";

export function initCode() {
  const blocks = document.querySelectorAll("figure.code");
  if (!blocks.length || !navigator.clipboard?.writeText) return;

  for (const fig of blocks) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "code__copy";
    btn.textContent = "Copy";
    btn.setAttribute("aria-label", `Copy ${fig.dataset.lang || ""} code`.replace(/\s+/g, " "));
    let timer;
    btn.addEventListener("click", async () => {
      const code = fig.querySelector("pre code") || fig.querySelector("pre");
      // textContent keeps the exact source text (innerText would add breaks for Chroma's line spans).
      const text = (code?.textContent || "").replace(/\n$/, "");
      try {
        await navigator.clipboard.writeText(text);
        btn.textContent = "Copied";
        btn.dataset.copied = "";
        announce("Code copied to clipboard");
      } catch {
        btn.textContent = "Failed";
        announce("Copying failed");
      }
      clearTimeout(timer);
      timer = setTimeout(() => {
        btn.textContent = "Copy";
        delete btn.dataset.copied;
      }, 1500);
    });
    fig.append(btn);
  }
}
