// Copy buttons for code blocks (figure.code). Hidden entirely when the Clipboard API is missing.
export function initCode() {
  const blocks = document.querySelectorAll("figure.code");
  if (!blocks.length || !navigator.clipboard?.writeText) return;

  const status = document.createElement("p");
  status.className = "sr-only";
  status.setAttribute("role", "status");
  document.body.append(status);

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
        status.textContent = "Code copied to clipboard";
      } catch {
        btn.textContent = "Failed";
        status.textContent = "Copying failed";
      }
      clearTimeout(timer);
      timer = setTimeout(() => {
        btn.textContent = "Copy";
        delete btn.dataset.copied;
        status.textContent = "";
      }, 1500);
    });
    fig.append(btn);
  }
}
