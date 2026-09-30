// 404 page: show the requested path in the fake shell output.
export function initNotFound() {
  const els = document.querySelectorAll("[data-404-path]");
  if (!els.length) return;
  let path = location.pathname;
  try {
    path = decodeURIComponent(path);
  } catch {
    /* keep it encoded */
  }
  const base = els[0].dataset.base || "/";
  const shown = path.startsWith(base) ? `~/${path.slice(base.length)}` : path;
  for (const el of els) el.textContent = shown.replace(/\/$/, "") || "~";
}
