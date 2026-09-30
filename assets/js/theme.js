// Theme toggle. The inline <head> script applies the stored theme before first paint;
// this keeps the toggle label and theme-color in sync and persists the choice.
const KEY = "theme";
const COLORS = { dark: "#0b0e14", light: "#ffffff" };

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
    root.dataset.theme = theme;
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
