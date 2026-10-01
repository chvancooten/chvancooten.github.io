// Theme toggle. The inline <head> script applies the stored theme before first paint;
// this keeps the toggle label and theme-color in sync, persists the choice, and tells
// listeners (the hero scene) through a "themechange" event on document.
const KEY = "theme";
const COLORS = { dark: "#100f0f", light: "#fffcf0" }; // Flexoki black and paper

export function initTheme() {
  const root = document.documentElement;
  const buttons = document.querySelectorAll("[data-theme-toggle]");
  const meta = document.querySelector('meta[name="theme-color"]');
  const current = () => (root.dataset.theme === "light" ? "light" : "dark");

  const sync = () => {
    const theme = current();
    const label = `Switch to ${theme === "dark" ? "light" : "dark"} theme`;
    for (const b of buttons) {
      b.setAttribute("aria-label", label);
      b.title = label;
    }
    if (meta) meta.content = COLORS[theme];
  };

  const apply = (theme, persist) => {
    const changed = root.dataset.theme !== theme;
    root.dataset.theme = theme;
    if (changed) document.dispatchEvent(new CustomEvent("themechange", { detail: theme }));
    if (persist) {
      try {
        localStorage.setItem(KEY, theme);
      } catch {
        /* storage unavailable: the choice lasts for this page only */
      }
    }
    sync();
  };

  for (const b of buttons) {
    b.addEventListener("click", () => apply(current() === "dark" ? "light" : "dark", true));
  }
  // Keep other open tabs in step.
  window.addEventListener("storage", (e) => {
    if (e.key === KEY && (e.newValue === "dark" || e.newValue === "light")) apply(e.newValue, false);
  });
  sync();
}
